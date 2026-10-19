"""Cross-host rules correlate only enrolled hosts and administrator-owned addresses."""
import json


def lateral_rules(db, host, event, now, host_addresses):
    results = []
    if event.kind in ("auth_failure", "auth_success") and event.source_ip:
        rows = db.execute(
            "SELECT host,kind,payload FROM events WHERE ip=? AND occurred BETWEEN ? AND ? "
            "AND kind IN ('auth_failure','auth_success')",
            (event.source_ip, now - 300, now + 30)).fetchall()
        failed = [r for r in rows if r['kind'] == 'auth_failure']
        targets = sorted({r['host'] for r in failed})
        if len(targets) >= 3 and len(failed) >= 10:
            results.append((host, 'cross_host_password_spray', event.source_ip, 'high',
                            json.dumps({'targets': targets, 'failures': len(failed)})))
        if event.user:
            targets = sorted({r['host'] for r in rows if r['kind'] == 'auth_success'
                              and json.loads(r['payload']).get('user') == event.user})
            if len(targets) >= 3:
                results.append((host, 'remote_login_fanout', event.source_ip, 'high',
                                json.dumps({'targets': targets, 'user': event.user})))
    # Check both sides for out-of-order delivery. The addresses come from local service
    # configuration, not an agent-supplied host name or destination field.
    source_hosts = {host} if event.kind in ('process_alert', 'malware_detection', 'process_start') else set()
    if event.kind == 'auth_success' and event.source_ip in host_addresses:
        source_hosts.add(host_addresses[event.source_ip])
    for source_host in sorted(source_hosts):
        signals = db.execute(
            "SELECT occurred,id FROM events WHERE host=? AND kind IN "
            "('process_alert','malware_detection','process_start') AND occurred BETWEEN ? AND ? AND (kind!='process_start' OR EXISTS (SELECT 1 FROM alerts WHERE alerts.event_id=events.id AND alerts.host=events.host AND alerts.rule IN ('web_server_shell','writable_directory_execution')))",
            (source_host, now - 300, now + 30)).fetchall()
        addresses = sorted(ip for ip, name in host_addresses.items() if name == source_host)
        for address in addresses:
            logins = db.execute(
                "SELECT host,id,occurred FROM events WHERE kind='auth_success' AND ip=? "
                "AND host!=? AND occurred BETWEEN ? AND ?",
                (address, source_host, now - 300, now + 30)).fetchall()
            for login in logins:
                matching = [s for s in signals if s['occurred'] <= login['occurred']]
                if matching:
                    results.append((login['host'], 'suspected_lateral_movement', address, 'critical',
                                    json.dumps({'source_host': source_host, 'target_host': login['host'],
                                                'signal_event_id': matching[-1]['id'],
                                                'login_event_id': login['id']})))
    return results
