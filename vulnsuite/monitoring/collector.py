"""Read-only, bounded local telemetry collection. Never exports raw log messages."""
import collections
import datetime as dt
import glob
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request

STATE = Path(os.environ.get('VULNSUITE_STATE', '/var/lib/vulnsuite-monitor'))

def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError('Command failed (exit %s)' % result.returncode)
    return result.stdout

def tail(path, size=262144):
    with open(path, 'rb') as f:
        f.seek(0, 2)
        total = f.tell()
        f.seek(max(0, total-size))
        data = f.read(size).decode('utf-8', errors='replace')
    return data.splitlines()[1:] if total > size else data.splitlines()

def value(v):
    return v.get('value', v.get('$type')) if isinstance(v, dict) else v

def collect():
    now = time.time()
    sources, alerts = [], []
    def source(name, scope, fn):
        try:
            details = fn()
            sources.append(dict(name=name, status='connected', scope=scope, checked_at=now, details=details))
            return details
        except Exception as exc:
            sources.append(dict(name=name, status='unavailable', scope=scope, checked_at=now, error=type(exc).__name__ + ': ' + str(exc)[:120], details={}))
            return None
    def defender_health():
        d = json.loads(command('/usr/bin/mdatp', 'health', '--output', 'json'))
        fields = ['healthy','licensed','realTimeProtectionEnabled','definitionsStatus','definitionsUpdatedMinutesAgo','definitionsVersion','networkProtectionStatus']
        return {k:value(d.get(k)) for k in fields}
    defender = source('Microsoft Defender health', 'Live local endpoint protection health', defender_health)
    if defender:
        if defender.get('healthy') is False or defender.get('realTimeProtectionEnabled') is False:
            alerts.append(dict(severity='high', title='Defender health or real-time protection needs attention', source='Microsoft Defender health'))
    def threats():
        data = json.loads(command('/usr/bin/mdatp','threat','list','--output','json'))['threats']
        if isinstance(data, dict) and isinstance(data.get('scans'), list):
            data = [t for scan in data['scans'] for t in scan.get('threats', [])]
        if not isinstance(data, list):
            raise ValueError('Unexpected threat response')
        return {'recorded_threats':len(data), 'scope':'Local threat history; includes previously remediated detections'}
    threat = source('Microsoft Defender detections','Local threat history; not a cloud incident feed', threats)
    if threat and threat['recorded_threats']:
        alerts.append(dict(severity='review', title='%s recorded Defender detections — review endpoint console for remediation status' % threat['recorded_threats'], source='Microsoft Defender detections'))
    def services():
        data = json.loads(command('/usr/bin/systemctl','list-units','--type=service','--all','--output=json','--no-pager'))
        return {'running':sum(x['sub']=='running' for x in data), 'failed':[x['unit'] for x in data if x['active']=='failed'], 'security_agents':[{ 'unit':x['unit'], 'state':x['active']} for x in data if any(y in x['unit'] for y in ['mdatp','auditd','azuremonitor','site24x7','sshd'])]}
    svc = source('Systemd services', 'Local service and monitoring-agent state', services)
    if svc and svc['failed']:
        alerts.append(dict(severity='warning', title='%s failed system services' % len(svc['failed']), source='Systemd services'))
    def ssh():
        rows = [json.loads(x) for x in command('/usr/bin/journalctl','-u','sshd','--since','1 hour ago','-n','2000','--no-pager','-o','json').splitlines() if x.startswith('{')]
        msgs = [str(x.get('MESSAGE','')) for x in rows]
        return {'window':'Last hour, at most 2,000 journal entries', 'entries':len(rows), 'failed_auth_events':sum(bool(re.search(r'Failed password|authentication failure|Invalid user',m)) for m in msgs), 'accepted_auth_events':sum('Accepted ' in m for m in msgs), 'sample_capped':len(rows)==2000}
    auth = source('SSH authentication journal','Aggregated authentication activity; raw identities omitted',ssh)
    if auth and auth['failed_auth_events']:
        alerts.append(dict(severity='warning', title='%s failed SSH authentication events in the sampled last hour' % auth['failed_auth_events'], source='SSH authentication journal'))
    def audit():
        path = '/var/log/audit/audit.log'
        rows = tail(path)
        types = collections.Counter(m.group(1) for x in rows if (m := re.search(r'^type=(\w+)', x)))
        return {'sample_records':len(rows),'event_types':dict(types.most_common(12)), 'last_write':os.stat(path).st_mtime, 'scope':'Latest 256 KiB of audit log; records are not unique incidents'}
    source('Linux audit log','Read-only audit record counters',audit)
    def nginx():
        result = []
        for p in sorted(glob.glob('/var/log/nginx/*access*.log')):
            rows = tail(p)
            codes = collections.Counter(m.group(1) for x in rows if (m := re.search(r'"\s+(\d{3})\s',x)))
            result.append({'log':Path(p).name,'sample_requests':sum(codes.values()),'status_codes':dict(codes),'last_write':os.stat(p).st_mtime})
        if not result:
            raise FileNotFoundError('No Nginx access logs found')
        return {'scope':'Latest 256 KiB per access log; sampled historical requests, not a fixed time window','logs':result}
    source('Nginx access logs','HTTP status aggregates; URLs and client addresses omitted',nginx)
    def docker():
        rows = [json.loads(x) for x in command('/usr/bin/docker','ps','-a','--format','{{json .}}').splitlines()]
        return {'containers':[{'name':x['Names'],'image':x['Image'],'state':x['State'],'status':x['Status']} for x in rows], 'scope':'Inventory and runtime status only; no image vulnerability scan'}
    source('Docker inventory','Read-only container runtime inventory',docker)
    def sockets():
        rows = command('/usr/sbin/ss','-H','-lnt').splitlines()
        return {'listeners':sorted(set(x.split()[3] for x in rows if len(x.split())>3)), 'scope':'Local TCP listening sockets; no network scan'}
    listeners = source('TCP listeners','Local exposure inventory',sockets)
    if listeners:
        baseline_path = STATE / 'listeners-baseline.json'
        try:
            baseline = json.loads(baseline_path.read_text())
        except FileNotFoundError:
            baseline = listeners['listeners']
            baseline_path.write_text(json.dumps(baseline))
        added = sorted(set(listeners['listeners']) - set(baseline))
        listeners['new_since_baseline'] = added
        if added:
            alerts.append(dict(severity='review',title='New TCP listeners since deployment baseline: ' + ', '.join(added),source='TCP listeners'))
    def findings():
        query = "SELECT json_build_object('assets',(SELECT count(*) FROM assets WHERE tenant_id='00000000-0000-0000-0000-000000000001'),'open_findings',count(*),'high_severity',count(*) FILTER (WHERE severity IN ('high','critical')),'last_seen',max(last_seen)) FROM findings WHERE status='open' AND tenant_id='00000000-0000-0000-0000-000000000001'"
        details = json.loads(command('/usr/bin/docker','exec','vulnsuite-postgres-1','psql','-U','vulnsuite','-d','vulnsuite','-tAc',query))
        try:
            details['scheduled_scan'] = json.loads(Path('/mnt/harshitrathi/vulnsuite/runtime/local-scan.json').read_text())
        except (OSError,ValueError):
            details['scheduled_scan'] = {'status':'No successful local scan recorded'}
        return details
    scan = source('VulnSuite scanner findings','Dedicated PostgreSQL database; hourly Bandit scan of VulnSuite source only',findings)
    if scan and scan['high_severity']:
        alerts.append(dict(severity='review',title=str(scan['high_severity']) + ' high/critical severity static-analysis findings require triage (not confirmed intrusions)',source='VulnSuite scanner findings'))
    if scan and now-scan.get('scheduled_scan',{}).get('last_success',0)>7200:
        alerts.append(dict(severity='warning',title='No successful local source scan within two hours',source='Local scan freshness'))
    def protection():
        token = Path('/mnt/harshitrathi/vulnsuite/runtime/protection/viewer-token').read_text().strip()
        request = urllib.request.Request('http://127.0.0.1:8139/v1/overview', headers={'Authorization':'Bearer '+token})
        with urllib.request.urlopen(request,timeout=10) as response:
            data = json.load(response)
        return {'hosts':data['hosts'], 'alerts':[{'id':a['id'],'rule':a.get('rule'), 'severity':a.get('severity'), 'host':a.get('host'), 'created':a.get('created'), 'review_status':a.get('review_status')} for a in data['alerts'] if not a.get('suppressed')], 'response_mode':'Monitoring only; automatic blocking and quarantine disabled', 'scope':'SSH correlation, watched file integrity and process polling; process visibility depends on OS permissions'}
    intrusion = source('VulnSuite protection agent','10-second collection: SSH, HTTP 401/403 correlation, file integrity and process signals',protection)
    if intrusion:
        for host in intrusion['hosts']:
            if host.get('stale'):
                alerts.append(dict(severity='high', title='Protection agent heartbeat is stale',source='VulnSuite protection agent'))
            if any(s.get('status') not in ('ok','disabled') or s.get('stale') for s in host.get('sensors',[])):
                alerts.append(dict(severity='warning',title='Protection agent has partial, stale or unavailable sensors; inspect source evidence',source='Protection sensor health'))
        open_alerts = [a for a in intrusion['alerts'] if a.get('review_status') not in ('resolved','false_positive')]
        if open_alerts:
            alerts.append(dict(severity='high',title=str(len(open_alerts))+' protection detection(s) need investigation in Operations',source='Protection detections'))
    def tools():
        names=['trivy','gitleaks','osv-scanner','trufflehog','dockle','kubescape','subfinder','httpx','nuclei','syft','cosign','kubectl','helm','testssl.sh','zap.sh']
        return {'binaries':{n:Path('/mnt/harshitrathi/vulnsuite/.tools/bin',n).exists() for n in names}, 'python_tools':{n:Path('/mnt/harshitrathi/vulnsuite/.venv/bin',n).exists() for n in ['bandit','pip-audit','semgrep']}, 'cloud_iac_tools':{n:Path('/mnt/harshitrathi/vulnsuite/.tools',n,'bin',n).exists() for n in ['prowler','checkov']}, 'nmap':Path('/mnt/harshitrathi/vulnsuite/.tools/bin/nmap').exists(), 'note':'Installed does not mean configured or recently scanned. Cloud, cluster and active scan targets are not configured.'}
    source('Scanner installation inventory','Local tool availability; separate from scan results',tools)
    for name, scope in [('Azure Monitor / Sentinel cloud events','Azure Monitor agents detected locally; cloud workspace credentials and query endpoint are not configured'),('Site24x7 cloud alerts','Agent detected locally; cloud API credentials are not configured')]:
        sources.append(dict(name=name,status='not configured',scope=scope,checked_at=now,details={}))
    for item in sources:
        if item['status'] == 'unavailable':
            alerts.append(dict(severity='warning', title=item['name'] + ' telemetry unavailable', source=item['name']))
    events_path = STATE / 'events.json'
    try:
        events = json.loads(events_path.read_text())
    except (OSError, ValueError):
        events = []
    events = [e for e in events if e['last_seen'] > now-7*86400]
    active_sources = {a['source'] for a in alerts}
    for e in events:
        if e['active'] and e['source'] not in active_sources:
            e['active'] = False
            e['resolved_at'] = now
    for a in alerts:
        previous = next((e for e in events if e['active'] and e['source'] == a['source']), None)
        if previous:
            previous.update(a, last_seen=now)
        else:
            events.append(dict(a, active=True, first_seen=now, last_seen=now))
    snapshot = dict(events=events[-1000:], collected_at=now, interval_seconds=60, host='10.91.16.86',sources=sources,alerts=alerts)
    STATE.mkdir(parents=True, exist_ok=True)
    history_path = STATE / 'history.json'
    try:
        history = json.loads(history_path.read_text())
    except (FileNotFoundError, ValueError):
        history=[]
    history = [x for x in history if x['time'] > now-86400][-1439:]
    history.append(dict(time=now,connected=sum(x['status']=='connected' for x in sources),alerts=len(alerts)))
    for name, data in [('snapshot.json',snapshot),('history.json',history),('events.json',events[-1000:])]:
        tmp = STATE / (name+'.tmp')
        tmp.write_text(json.dumps(data))
        tmp.chmod(0o644)
        tmp.replace(STATE/name)

if __name__ == '__main__':
    collect()
