"""Single-organisation operational store; separate from the suite's tenant database.

An instance has exactly one organisation, a separate DB and distinct per-host keys.
No API-supplied tenant identifier is trusted. SQL operations are transactional.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .models import Event
from .operations_store import OperationsMixin
from .detection import lateral_rules


class Store(OperationsMixin):
    def __init__(self, path: str, host_addresses: dict | None = None, retention_days: int = 7):
        self.path = path
        if not 1 <= retention_days <= 365:
            raise ValueError("retention_days must be between 1 and 365")
        self.retention_days = retention_days
        self.host_addresses = host_addresses or {}
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events (
                    host TEXT NOT NULL, id TEXT NOT NULL, received REAL NOT NULL,
                    occurred REAL NOT NULL, kind TEXT NOT NULL, ip TEXT, payload TEXT NOT NULL,
                    PRIMARY KEY(host,id));
                CREATE INDEX IF NOT EXISTS event_window ON events(host,kind,ip,occurred);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY, host TEXT NOT NULL, rule TEXT NOT NULL,
                    ip TEXT, severity TEXT NOT NULL, created REAL NOT NULL,
                    event_id TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS alert_window ON alerts(host,rule,ip,created);
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY, host TEXT NOT NULL, alert_id INTEGER NOT NULL,
                    ip TEXT NOT NULL, duration INTEGER NOT NULL, created REAL NOT NULL,
                    status TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT);
                CREATE INDEX IF NOT EXISTS cross_host_window ON events(ip,kind,occurred);
                CREATE TABLE IF NOT EXISTS sensors (
                    host TEXT NOT NULL, sensor TEXT NOT NULL, status TEXT NOT NULL,
                    detail TEXT NOT NULL, received REAL NOT NULL, PRIMARY KEY(host,sensor));
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL, action TEXT NOT NULL,
                    subject TEXT NOT NULL, detail TEXT NOT NULL);
            """)

        self.init_operations()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def audit(db, action, subject, detail):
        db.execute("INSERT INTO audit(at,action,subject,detail) VALUES(?,?,?,?)",
                   (datetime.now(timezone.utc).timestamp(), action, subject, detail))

    def ingest(self, host: str, events: list[Event], now: float) -> list[dict]:
        alerts = []
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Only accepted events within five minutes can influence current detections.
            for event in events:
                stamp = event.occurred_at.timestamp()
                if not now - self.retention_days * 86400 <= stamp <= now + 30:
                    raise ValueError("event timestamp outside configured archive retention window")
                payload = event.model_dump_json()
                existing = db.execute("SELECT payload FROM events WHERE host=? AND id=?",
                                      (host, str(event.event_id))).fetchone()
                if existing:
                    if Event.model_validate_json(existing[0]).model_dump_json() != payload:
                        raise ValueError("event_id reused with different contents")
                    continue
                db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                           (host, str(event.event_id), now, stamp, event.kind,
                            event.source_ip, payload))
                # Older telemetry is archived but must not trigger current response or refresh health.
                if stamp < now - 300:
                    continue
                self.update_host_metadata(db, host, event, now)
                rules = []
                if event.kind in ("auth_failure", "api_denied") and event.source_ip:
                    count = db.execute(
                        "SELECT count(*) FROM events WHERE host=? AND kind=? AND ip=? "
                        "AND occurred BETWEEN ? AND ?",
                        (host, event.kind, event.source_ip, now - 300, now + 30),
                    ).fetchone()[0]
                    threshold = 5 if event.kind == "auth_failure" else 20
                    if count >= threshold:
                        rule = ("ssh_brute_force" if event.protocol in (None, "ssh") else "remote_auth_brute_force") if event.kind == "auth_failure" else "api_access_abuse"
                        rules.append((rule, "high", f"{count} access events in 5 minutes"))
                if event.kind in ("auth_failure", "auth_success") and event.source_ip:
                    # Query both sides so retried/out-of-order batches correlate correctly.
                    failures = db.execute(
                        "SELECT occurred FROM events WHERE host=? AND kind='auth_failure' "
                        "AND ip=? AND occurred>=?", (host, event.source_ip, now - 300),
                    ).fetchall()
                    successes = db.execute(
                        "SELECT occurred FROM events WHERE host=? AND kind='auth_success' "
                        "AND ip=? AND occurred>=?", (host, event.source_ip, now - 300),
                    ).fetchall()
                    if any(sum(s[0] - 300 <= f[0] <= s[0] for f in failures) >= 5
                           for s in successes):
                        rules.append(("login_after_brute_force", "critical",
                                      "Successful remote authentication after repeated failures from the same IP"))
                if event.kind == "file_change":
                    rules.append(("file_integrity_change", "high",
                                  json.dumps({"path": event.path, "change": event.change})))
                if event.kind == "process_start":
                    import ntpath
                    executable = event.executable or ""
                    parent = ntpath.basename(event.parent_executable or "").lower()
                    name = ntpath.basename(executable).lower()
                    if (parent in {"w3wp.exe", "httpd.exe", "nginx.exe", "nginx", "apache2", "httpd", "php-fpm"}
                            and name in {"cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash"}):
                        rules.append(("web_server_shell", "high", json.dumps({"pid": event.pid,
                            "executable": executable, "parent_executable": event.parent_executable,
                            "telemetry_source": event.telemetry_source})))
                    if executable.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) or "\\appdata\\local\\temp\\" in executable.lower():
                        rules.append(("writable_directory_execution", "high", json.dumps({
                            "pid": event.pid, "executable": executable, "telemetry_source": event.telemetry_source})))
                if event.kind == "process_alert":
                    rules.append((event.process_rule, "high", json.dumps({
                        "pid": event.pid, "ppid": event.ppid, "start_ticks": event.start_ticks,
                        "executable": event.executable, "parent_executable": event.parent_executable})))
                if event.kind == "malware_detection":
                    rules.append(("malware_detected", "critical", json.dumps({
                        "path": event.path, "engine": event.engine, "signature": event.signature,
                        "sha256": event.sha256, "pid": event.pid, "start_ticks": event.start_ticks})))
                if event.kind == "waf_match":
                    rules.append(("waf_rule_match", "high", json.dumps({
                        "rule_ids": event.rule_ids, "action": event.waf_action})))
                if event.kind == "sensor_status":
                    db.execute("INSERT INTO sensors VALUES(?,?,?,?,?) ON CONFLICT(host,sensor) "
                               "DO UPDATE SET status=excluded.status,detail=excluded.detail,received=excluded.received",
                               (host, event.sensor, event.sensor_status, event.sensor_detail, now))
                    if event.sensor_status != "ok":
                        rules.append(("sensor_degraded", "medium", json.dumps({
                            "sensor": event.sensor, "status": event.sensor_status, "detail": event.sensor_detail})))
                expanded = [(host, rule, event.source_ip, severity, detail) for rule, severity, detail in rules]
                for phase in range(2):
                    if phase:
                        expanded = lateral_rules(db, host, event, now, self.host_addresses)
                    for alert_host, rule, ip, severity, detail in expanded:
                        recent = db.execute(
                            "SELECT 1 FROM alerts WHERE host=? AND rule=? AND ip IS ? "
                            "AND created>? AND (? NOT IN ('file_integrity_change','malware_detected',"
                            "'web_server_shell','writable_directory_execution','deleted_executable','sensor_degraded') OR detail=?)",
                            (alert_host, rule, ip, now - 300, rule, detail),
                        ).fetchone()
                        if recent:
                            continue
                        cursor = db.execute(
                            "INSERT INTO alerts(host,rule,ip,severity,created,event_id,detail) "
                            "VALUES(?,?,?,?,?,?,?)",
                            (alert_host, rule, ip, severity, now, str(event.event_id), detail),
                        )
                        alert = dict(db.execute("SELECT * FROM alerts WHERE id=?",
                                                (cursor.lastrowid,)).fetchone())
                        alerts.append(alert)
                        self.record_operational_alert(db, alert, now)
                        self.audit(db, "alert_created", alert_host, str(cursor.lastrowid))
            # Retention cleanup is explicit and protects incident-linked evidence (maintenance.py).
            db.execute("UPDATE commands SET status='expired' WHERE status='pending' AND created<?",
                       (now - 300,))
        return alerts

    def list_alerts(self, limit=100):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]
