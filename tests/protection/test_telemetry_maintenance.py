import json
import sqlite3
import time
from datetime import datetime, timezone

import pytest

from vulnsuite.protection.evaluation import evaluate
from vulnsuite.protection.maintenance import backup_database, restore_database, sha256_file, prune, monitor_health
from vulnsuite.protection.models import Event
from vulnsuite.protection.store import Store


def test_online_backup_includes_wal_restore_integrity_and_no_overwrite(tmp_path):
    database, backup, restored = tmp_path / 'live.db', tmp_path / 'backup.db', tmp_path / 'restored.db'
    store = Store(str(database))
    # Keep an open connection so committed data still has a live WAL sidecar.
    with store.connect() as live:
        live.execute("INSERT INTO audit(at,action,subject,detail) VALUES(1,'fixture','tester','{}')")
        live.commit()
        result = backup_database(database, backup, 'test-admin')
    assert result['sha256'] == sha256_file(backup)
    with pytest.raises(FileExistsError):
        backup_database(database, backup)
    with pytest.raises(ValueError):
        restore_database(backup, restored, '0' * 64)
    assert not restored.exists()
    receipt = restore_database(backup, restored, result['sha256'], 'restore-admin')
    assert receipt['integrity'] == 'ok'
    with sqlite3.connect(restored) as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        actions = {r[0] for r in db.execute('SELECT action FROM audit')}
        assert {'fixture', 'backup_snapshot_created', 'database_restored'} <= actions
    original = sha256_file(restored)
    with pytest.raises(FileExistsError):
        restore_database(backup, restored, result['sha256'])
    assert sha256_file(restored) == original
    broken = tmp_path / 'broken.db'
    broken.write_bytes(b'not SQLite')
    with pytest.raises(sqlite3.DatabaseError):
        restore_database(broken, tmp_path / 'never.db', sha256_file(broken))
    assert not (tmp_path / 'never.db').exists()


def test_retention_preview_then_preserves_incident_response_evidence_and_audit(tmp_path):
    now = time.time()
    old = now - 100 * 86400
    store = Store(str(tmp_path / 'live.db'))
    with store.connect() as db:
        for n in range(1, 5):
            at = old + n * 1000
            item = Event(kind='heartbeat', occurred_at=datetime.fromtimestamp(at, timezone.utc))
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', ('a', str(item.event_id), at, at, item.kind, None, item.model_dump_json()))
            db.execute('INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?)',
                       (n, 'a', 'fixture', None, 'high', at, str(item.event_id), '{}'))
        db.execute("INSERT INTO incidents VALUES('i','investigation','alice','open','high',?,?,1)", (old, old))
        db.execute("INSERT INTO incident_alerts VALUES('i',1)")
        db.execute("INSERT INTO commands VALUES(1,'a',2,'10.1.1.1',300,?,'pending','reason',NULL)", (old,))
        db.execute("INSERT INTO response_jobs(id,host,action,alert_id,plan,status,requested_by,created,expires) "
                   "VALUES('job','a','quarantine_file',3,'{}','approved','alice',?,?)", (old, now + 100))
        db.execute("INSERT INTO alert_reviews VALUES(4,'resolved','alice',?,'investigated')", (old,))
        db.execute("INSERT INTO audit(at,action,subject,detail) VALUES(?,'existing','alice','{}')", (old,))
    preview = prune(store.path, now=now)
    assert preview['eligible'] == {'events': 1, 'alerts': 1, 'deliveries': 0}
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM alerts').fetchone()[0] == 4
    applied = prune(store.path, apply=True, now=now)
    assert applied['applied']
    with store.connect() as db:
        assert {r[0] for r in db.execute('SELECT id FROM alerts')} == {1, 2, 3}
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 3
        assert db.execute('SELECT count(*) FROM alert_reviews').fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM audit WHERE action='existing'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM audit WHERE action='retention_applied'").fetchone()[0] == 1


def test_health_grace_dedup_recovery_preserves_incidents(tmp_path):
    now = time.time()
    store = Store(str(tmp_path / 'live.db'))
    store.seed_hosts({'old': {'token': 'o' * 40}, 'new': {'token': 'n' * 40}})
    with store.connect() as db:
        db.execute("UPDATE enrolled_hosts SET created=?,last_seen=? WHERE host='old'", (now - 1000, now - 500))
        db.execute("INSERT INTO sensors VALUES('old','telemetry','ok','collected',?)", (now - 500,))
    result = monitor_health(store.path, now=now, connectors=['soc'])
    assert len(result['created']) == 2
    assert monitor_health(store.path, now=now + 1)['created'] == []
    with store.connect() as db:
        assert {r[0] for r in db.execute('SELECT rule FROM alerts')} == {'agent_offline', 'sensor_stale'}
        assert db.execute('SELECT count(*) FROM deliveries').fetchone()[0] == 2
        db.execute("INSERT INTO incidents VALUES('i','Investigate outage','alice','investigating','high',?,?,1)", (now, now))
        db.execute("INSERT INTO incident_alerts VALUES('i',?)", (result['created'][0],))
        db.execute("INSERT INTO alert_reviews VALUES(?,'triaged','alice',?,'Investigating missing telemetry')",
                   (result['created'][0], now+1))
        db.execute("UPDATE enrolled_hosts SET last_seen=? WHERE host='old'", (now + 2,))
        db.execute("UPDATE sensors SET received=? WHERE host='old'", (now + 2,))
    recovery = monitor_health(store.path, now=now + 3)
    assert set(recovery['recovered']) == set(result['created'])
    with store.connect() as db:
        assert db.execute("SELECT status FROM incidents WHERE id='i'").fetchone()[0] == 'investigating'
        assert {r[0] for r in db.execute('SELECT status FROM alert_reviews')} == {'resolved'}
        assert db.execute('SELECT at FROM alert_reviews WHERE alert_id=?',
                          (result['created'][0],)).fetchone()[0] == now+1
    assert len(monitor_health(store.path, now=now + 200)['created']) == 2


def test_synthetic_evaluation_exposes_false_positive_limitation(tmp_path):
    result = evaluate(tmp_path / 'fixtures')
    assert len(result['cases']) == 8
    assert result['counts'] == {'true_positive': 5, 'false_positive': 1, 'true_negative': 2, 'false_negative': 0}
    assert result['synthetic_case_false_positive_rate'] == pytest.approx(1 / 3)
    assert 'not a production accuracy estimate' in result['scope']
