"""Explicit SQLite backup, restore, retention and loss-of-visibility checks.

No command runs on import. Restore never replaces an existing database; retention
is preview-only unless --apply is supplied. Use a private backup directory.
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


@contextmanager
def _database(path, readonly=False):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('database must be an existing regular file, not a symlink')
    db = sqlite3.connect(path.as_uri() + ('?mode=ro' if readonly else '?mode=rw'), uri=True, timeout=30)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        required = {'events', 'alerts', 'audit'}
        present = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required <= present:
            raise ValueError('not a VulnSuite protection database')
        yield db
    finally:
        db.close()


def _audit(db, action, actor, detail, now=None):
    db.execute('INSERT INTO audit(at,action,subject,detail) VALUES(?,?,?,?)',
               (time.time() if now is None else now, action, actor, json.dumps(detail, sort_keys=True)))


def _integrity(db):
    result = [row[0] for row in db.execute('PRAGMA integrity_check')]
    if result != ['ok']:
        raise ValueError('SQLite integrity check failed')


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _publish_snapshot(source, target, actor, action, detail):
    target = Path(target).absolute()
    if target.exists() or target.is_symlink():
        raise FileExistsError('target already exists; restore/backup never overwrites')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.vulnsuite-backup-', suffix='.db', dir=target.parent)
    os.close(fd)
    try:
        with _database(source, readonly=True) as origin:
            _integrity(origin)
            destination = sqlite3.connect(temporary)
            try:
                origin.backup(destination, pages=256, sleep=0.01)
                destination.execute('PRAGMA journal_mode=DELETE')
                with destination:
                    _audit(destination, action, actor, detail)
                _integrity(destination)
            finally:
                destination.close()
        with open(temporary, 'rb') as stream:
            os.fsync(stream.fileno())
        checksum = sha256_file(temporary)
        # Atomic exclusive publication: never replace a concurrently created file.
        os.link(temporary, target)
        if os.name != 'nt':
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return {'path': str(target), 'sha256': checksum, 'integrity': 'ok'}
    finally:
        for suffix in ('', '-journal', '-wal', '-shm'):
            try:
                Path(temporary + suffix).unlink()
            except FileNotFoundError:
                pass


def backup_database(database, target, actor='maintenance'):
    operation = uuid4().hex
    with _database(database) as db:
        with db:
            _audit(db, 'backup_started', actor, {'operation': operation})
    try:
        result = _publish_snapshot(database, target, actor, 'backup_snapshot_created', {'operation': operation})
    except Exception:
        with _database(database) as db:
            with db:
                _audit(db, 'backup_failed', actor, {'operation': operation})
        raise
    with _database(database) as db:
        with db:
            _audit(db, 'backup_completed', actor, {'operation': operation, **result})
    return result


def restore_database(backup, target, expected_sha256, actor='maintenance'):
    if not isinstance(expected_sha256, str) or not re.fullmatch('[a-fA-F0-9]{64}', expected_sha256):
        raise ValueError('expected SHA256 checksum required')
    # Refuse sidecar WALs: backups produced here are standalone DELETE-journal snapshots.
    if Path(str(backup) + '-wal').exists():
        raise ValueError('restore input must be a standalone backup without a WAL')
    target = Path(target).absolute()
    if target.exists() or target.is_symlink():
        raise FileExistsError('restore target already exists')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Pin the exact bytes whose checksum is verified, avoiding a source-file
    # change between validation and SQLite restore.
    with tempfile.TemporaryDirectory(prefix='.vulnsuite-restore-', dir=target.parent) as folder:
        staged = Path(folder) / 'verified.db'
        digest = hashlib.sha256()
        source_fd = os.open(backup, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(source_fd, 'rb') as source, open(staged, 'xb') as destination:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError('restore source must be a regular file')
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if digest.hexdigest() != expected_sha256.lower():
            raise ValueError('backup SHA256 differs from expected checksum')
        return _publish_snapshot(staged, target, actor, 'database_restored',
                                 {'backup_sha256': expected_sha256.lower()})


def _days(value):
    if type(value) is not int or not 1 <= value <= 3650:
        raise ValueError('retention must be an integer from 1 to 3650 days')
    return value


def prune(database, event_days=7, alert_days=90, delivery_days=30, apply=False, actor='maintenance', now=None):
    now = time.time() if now is None else now
    event_before = now - _days(event_days) * 86400
    alert_before = now - _days(alert_days) * 86400
    delivery_before = now - _days(delivery_days) * 86400
    with _database(database) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('CREATE TEMP TABLE protected_alerts(id INTEGER PRIMARY KEY)')
            for query in ('SELECT alert_id FROM incident_alerts', 'SELECT alert_id FROM commands',
                          'SELECT alert_id FROM response_jobs'):
                db.execute('INSERT OR IGNORE INTO protected_alerts ' + query)
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='maintenance_health'").fetchone():
                db.execute('INSERT OR IGNORE INTO protected_alerts SELECT alert_id FROM maintenance_health WHERE active=1')
            # In-flight webhook jobs retain their exact security alert as well as payload.
            for row in db.execute("SELECT payload FROM deliveries WHERE status!='delivered'"):
                try:
                    payload = json.loads(row['payload'])
                    identifier = payload.get('data', {}).get('id')
                    if payload.get('type') == 'security.alert' and type(identifier) is int:
                        db.execute('INSERT OR IGNORE INTO protected_alerts VALUES(?)', (identifier,))
                except (ValueError, TypeError, AttributeError):
                    # Unknown worker data is never deleted by this maintenance task.
                    pass
            db.execute('CREATE TEMP TABLE expired_alerts(id INTEGER PRIMARY KEY)')
            db.execute('INSERT INTO expired_alerts SELECT id FROM alerts WHERE created<? '
                       'AND id NOT IN (SELECT id FROM protected_alerts)', (alert_before,))
            counts = {'alerts': db.execute('SELECT count(*) FROM expired_alerts').fetchone()[0]}
            # Keep supporting evidence around every retained alert across hosts; this
            # preserves the correlation window for cross-host attacks and incidents.
            event_filter = '''received<? AND NOT EXISTS (
                SELECT 1 FROM alerts a WHERE a.id NOT IN (SELECT id FROM expired_alerts)
                AND (a.event_id=events.id OR events.occurred BETWEEN a.created-300 AND a.created+30))'''
            counts['events'] = db.execute('SELECT count(*) FROM events WHERE ' + event_filter,
                                         (event_before,)).fetchone()[0]
            counts['deliveries'] = db.execute("SELECT count(*) FROM deliveries WHERE status='delivered' AND created<?",
                                             (delivery_before,)).fetchone()[0]
            result = {'applied': apply, 'event_days': event_days, 'alert_days': alert_days,
                      'delivery_days': delivery_days, 'eligible': counts,
                      'preserved': 'incidents, response histories, active health alerts, audit, policies and retained alert evidence'}
            if apply:
                db.execute('DELETE FROM events WHERE ' + event_filter, (event_before,))
                for table in ('alert_reviews', 'suppressed_alerts'):
                    db.execute(f'DELETE FROM {table} WHERE alert_id IN (SELECT id FROM expired_alerts)')
                db.execute('DELETE FROM alerts WHERE id IN (SELECT id FROM expired_alerts)')
                db.execute("DELETE FROM deliveries WHERE status='delivered' AND created<?", (delivery_before,))
                _audit(db, 'retention_applied', actor, result, now)
                db.execute('INSERT INTO maintenance_runs(at,detail) VALUES(?,?)', (now, json.dumps(result)))
                db.commit()
            else:
                db.rollback()
            return result
        except Exception:
            db.rollback()
            raise


def monitor_health(database, stale_seconds=120, grace_seconds=300, actor='maintenance', now=None, connectors=()):
    if type(stale_seconds) is not int or not 30 <= stale_seconds <= 86400:
        raise ValueError('stale_seconds must be 30..86400')
    if type(grace_seconds) is not int or not stale_seconds <= grace_seconds <= 604800:
        raise ValueError('grace_seconds must be >= stale_seconds and <=604800')
    now = time.time() if now is None else now
    # Validate existence before Store can create anything; optional schema upgrades are local.
    with _database(database):
        pass
    from .store import Store
    store = Store(str(database))
    store.connector_names = list(connectors)
    result = {'created': [], 'recovered': []}
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('''CREATE TABLE IF NOT EXISTS maintenance_health (
            host TEXT NOT NULL,sensor TEXT NOT NULL,alert_id INTEGER NOT NULL,
            active INTEGER NOT NULL,PRIMARY KEY(host,sensor))''')
        active = {}
        for host in db.execute("SELECT host,created,last_seen FROM enrolled_hosts WHERE status='active'"):
            if now - host['created'] < grace_seconds:
                continue
            if now - (host['last_seen'] or host['created']) > stale_seconds:
                active[(host['host'], '')] = ('agent_offline', {'last_seen': host['last_seen']})
            for sensor in db.execute('SELECT sensor,received FROM sensors WHERE host=?', (host['host'],)):
                if now - sensor['received'] > stale_seconds:
                    active[(host['host'], sensor['sensor'])] = ('sensor_stale', {'sensor': sensor['sensor'], 'last_seen': sensor['received']})
        existing = {(r['host'], r['sensor']): dict(r) for r in db.execute('SELECT * FROM maintenance_health')}
        for key, (rule, detail) in active.items():
            if existing.get(key, {}).get('active'):
                continue
            detail['meaning'] = 'Telemetry is missing; investigate connectivity, agent and sensor health.'
            cursor = db.execute('INSERT INTO alerts(host,rule,ip,severity,created,event_id,detail) VALUES(?,?,NULL,?,?,?,?)',
                                (key[0], rule, 'high' if rule == 'agent_offline' else 'medium', now,
                                 'health:' + uuid4().hex, json.dumps(detail)))
            identifier = cursor.lastrowid
            db.execute('INSERT INTO maintenance_health VALUES(?,?,?,1) ON CONFLICT(host,sensor) '
                       'DO UPDATE SET alert_id=excluded.alert_id,active=1', (key[0], key[1], identifier))
            alert = dict(db.execute('SELECT * FROM alerts WHERE id=?', (identifier,)).fetchone())
            store.record_operational_alert(db, alert, now)
            _audit(db, 'health_alert_created', actor, {'alert_id': identifier, 'host': key[0], 'sensor': key[1]}, now)
            result['created'].append(identifier)
        for key, row in existing.items():
            if not row['active'] or key in active:
                continue
            # Revocation is not recovery: only fresh observed telemetry clears visibility alerts.
            fresh = db.execute("SELECT last_seen FROM enrolled_hosts WHERE host=? AND status='active'", (key[0],)).fetchone()
            if not fresh or not fresh[0] or now - fresh[0] > stale_seconds:
                continue
            if key[1]:
                sensor = db.execute('SELECT received FROM sensors WHERE host=? AND sensor=?', key).fetchone()
                if not sensor or now - sensor[0] > stale_seconds:
                    continue
            db.execute('UPDATE maintenance_health SET active=0 WHERE host=? AND sensor=?', key)
            db.execute("INSERT INTO alert_reviews(alert_id,status,actor,at,reason) VALUES(?,'resolved',?,?,?) "
                       "ON CONFLICT(alert_id) DO UPDATE SET status='resolved',actor=excluded.actor,reason=excluded.reason "
                       "WHERE alert_reviews.status IN ('open','triaged')",
                       (row['alert_id'], actor, now, 'Fresh telemetry restored; incident status remains operator-managed.'))
            _audit(db, 'health_visibility_restored', actor, {'alert_id': row['alert_id'], 'host': key[0]}, now)
            result['recovered'].append(row['alert_id'])
        _audit(db, 'health_monitor_completed', actor, result, now)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actor', default=getpass.getuser())
    commands = parser.add_subparsers(dest='command', required=True)
    backup = commands.add_parser('backup')
    backup.add_argument('--database', required=True)
    backup.add_argument('--target', required=True)
    restore = commands.add_parser('restore')
    restore.add_argument('--backup', required=True)
    restore.add_argument('--target', required=True)
    restore.add_argument('--sha256', required=True)
    cleanup = commands.add_parser('prune')
    cleanup.add_argument('--database', required=True)
    cleanup.add_argument('--event-days', type=int, default=7)
    cleanup.add_argument('--alert-days', type=int, default=90)
    cleanup.add_argument('--delivery-days', type=int, default=30)
    cleanup.add_argument('--apply', action='store_true')
    health = commands.add_parser('health')
    health.add_argument('--database', required=True)
    health.add_argument('--stale-seconds', type=int, default=120)
    health.add_argument('--grace-seconds', type=int, default=300)
    health.add_argument('--config', help='Optional private server config; queue its integration notifications only')
    args = parser.parse_args()
    if args.command == 'backup':
        result = backup_database(args.database, args.target, args.actor)
    elif args.command == 'restore':
        result = restore_database(args.backup, args.target, args.sha256, args.actor)
    elif args.command == 'prune':
        result = prune(args.database, args.event_days, args.alert_days, args.delivery_days, args.apply, args.actor)
    else:
        config = json.loads(Path(args.config).read_text()) if args.config else {}
        if args.config and Path(config['database']).resolve() != Path(args.database).resolve():
            raise ValueError('config database must match the explicitly selected database')
        result = monitor_health(args.database, args.stale_seconds, args.grace_seconds, args.actor,
                                connectors=config.get('integrations', {}))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
