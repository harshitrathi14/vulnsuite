"""Operational persistence shared by the API and explicitly run background workers."""
import hashlib
from ipaddress import ip_address
import json
import secrets
import time
from uuid import uuid4


class OperationsMixin:
    def init_operations(self):
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS enrolled_hosts (
                    host TEXT PRIMARY KEY, token_hash TEXT UNIQUE, status TEXT NOT NULL,
                    policy TEXT NOT NULL, created REAL NOT NULL, rotated REAL NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}', last_seen REAL);
                CREATE TABLE IF NOT EXISTS enrollment_tokens (
                    token_hash TEXT PRIMARY KEY,host TEXT NOT NULL,expires REAL NOT NULL,used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,title TEXT NOT NULL,owner TEXT NOT NULL,status TEXT NOT NULL,
                    severity TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,version INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS incident_alerts (
                    incident_id TEXT NOT NULL,alert_id INTEGER NOT NULL,PRIMARY KEY(incident_id,alert_id));
                CREATE TABLE IF NOT EXISTS incident_notes (
                    id INTEGER PRIMARY KEY,incident_id TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL,note TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS alert_reviews (
                    alert_id INTEGER PRIMARY KEY,status TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL,reason TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS suppressions (
                    id TEXT PRIMARY KEY,rule TEXT NOT NULL,host TEXT NOT NULL,ip TEXT,expires REAL NOT NULL,
                    reason TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS suppressed_alerts (
                    alert_id INTEGER PRIMARY KEY,suppression_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS deliveries (
                    id TEXT PRIMARY KEY,connector TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,next_attempt REAL NOT NULL,last_error TEXT,created REAL NOT NULL,lease_until REAL NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS response_jobs (
                    id TEXT PRIMARY KEY,host TEXT NOT NULL,action TEXT NOT NULL,alert_id INTEGER NOT NULL,
                    plan TEXT NOT NULL,status TEXT NOT NULL,requested_by TEXT NOT NULL,approved_by TEXT,
                    created REAL NOT NULL,expires REAL NOT NULL,result TEXT,lease_until REAL NOT NULL DEFAULT 0,next_attempt REAL NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS policy_history (
                    id INTEGER PRIMARY KEY,host TEXT NOT NULL,policy TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS maintenance_runs (
                    id INTEGER PRIMARY KEY,at REAL NOT NULL,detail TEXT NOT NULL);
            ''')
            for table, columns in {'deliveries': ['lease_until'],
                                   'response_jobs': ['lease_until','next_attempt','attempts']}.items():
                present = {row[1] for row in db.execute(f'PRAGMA table_info({table})')}
                for column in columns:
                    if column not in present:
                        db.execute(f'ALTER TABLE {table} ADD COLUMN {column} REAL NOT NULL DEFAULT 0')
        self.connector_names = []
        # Per-host pre-approved containment policy (service config `response.hosts`).
        self.response_policies = {}

    AUTO_RULES = ('ransomware_activity',)

    def automatic_response(self, db, alert, now):
        """Pre-approved host isolation for the configured critical rules.

        Opt-in twice: the service policy names the rules, duration and the
        administrator who pre-approved it, and the host's local response policy
        must allow automatic plans. The job is created already approved, marked
        automatic, audited, and expires like any other isolation; the agent still
        applies its own policy and reports a receipt.
        """
        policy = self.response_policies.get(alert['host'], {})
        auto = policy.get('automatic') if isinstance(policy, dict) else None
        if (not auto or not isinstance(auto, dict) or alert['rule'] not in auto.get('rules', [])
                or alert['rule'] not in self.AUTO_RULES or not policy.get('enabled')
                or 'isolate_host' not in policy.get('allowed_actions', [])):
            return None
        approver = auto.get('approved_by')
        duration = auto.get('isolate_seconds', 900)
        if not isinstance(approver, str) or not approver or type(duration) is not int or not 60 <= duration <= 3600:
            return None
        # One automatic isolation per host at a time; never stack timers.
        outstanding = db.execute("SELECT 1 FROM response_jobs WHERE host=? AND action='isolate_host' "
                                 "AND status IN ('requested','approved','applied') AND expires>?",
                                 (alert['host'], now)).fetchone()
        if outstanding:
            return None
        identifier = uuid4().hex
        try:
            if policy.get('platform', 'linux') == 'windows':
                from .windows_isolation import prepare_windows_isolation as prepare
            else:
                from .playbooks import prepare_isolation as prepare
            plan = prepare(policy.get('isolation', {}), duration, identifier, now=now)
        except (ValueError, TypeError, KeyError):
            self.audit(db, 'automatic_response_invalid', alert['host'],
                       json.dumps({'alert_id': alert['id'], 'rule': alert['rule']}))
            return None
        plan.update({'platform': policy.get('platform', 'linux'), 'automatic': True,
                     'reason': f"Automatic isolation pre-approved for {alert['rule']} (alert {alert['id']})"})
        db.execute('INSERT INTO response_jobs(id,host,action,alert_id,plan,status,requested_by,approved_by,created,expires) '
                   "VALUES(?,?,'isolate_host',?,?,'approved','policy:automatic',?,?,?)",
                   (identifier, alert['host'], alert['id'], json.dumps(plan), approver, now, plan['expires_at']))
        self.audit(db, 'playbook_auto_approved', approver,
                   json.dumps({'id': identifier, 'alert_id': alert['id'], 'rule': alert['rule'], 'plan': plan}))
        self.queue_notifications(db, 'response.automatic', {'id': identifier, 'host': alert['host'],
                                                            'rule': alert['rule'], 'expires_at': plan['expires_at']})
        return identifier

    @staticmethod
    def token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def seed_hosts(self, hosts):
        now = time.time()
        with self.connect() as db:
            for name, policy in hosts.items():
                safe = {k: v for k, v in policy.items() if k != 'token'}
                safe['addresses'] = sorted({str(ip_address(v)) for v in safe.get('addresses',[])})
                db.execute("INSERT OR IGNORE INTO enrolled_hosts(host,token_hash,status,policy,created,rotated) "
                           "VALUES(?,?,'active',?,?,?)", (name,self.token_hash(policy['token']),json.dumps(safe),now,now))

    def host_policies(self):
        with self.connect() as db:
            return {r['host']: json.loads(r['policy']) for r in db.execute(
                "SELECT host,policy FROM enrolled_hosts WHERE status='active'")}

    def authenticate_agent(self, token):
        with self.connect() as db:
            row = db.execute("SELECT host FROM enrolled_hosts WHERE token_hash=? AND status='active'",
                             (self.token_hash(token),)).fetchone()
            return row['host'] if row else None

    def queue_notifications(self, db, event_type, data):
        payload = json.dumps({'type': event_type, 'data': data}, separators=(',', ':'))
        now = time.time()
        for name in self.connector_names:
            db.execute("INSERT INTO deliveries(id,connector,payload,status,next_attempt,created) VALUES(?,?,?,'pending',?,?)",
                       (uuid4().hex, name, payload, now, now))

    def record_operational_alert(self, db, alert, now):
        suppression = db.execute(
            "SELECT id FROM suppressions WHERE revoked=0 AND expires>? AND rule=? AND host=? AND (ip IS NULL OR ip=?) "
            "ORDER BY created DESC LIMIT 1", (now,alert['rule'],alert['host'],alert['ip'])).fetchone()
        if suppression:
            db.execute('INSERT OR IGNORE INTO suppressed_alerts VALUES(?,?)', (alert['id'],suppression['id']))
        else:
            self.queue_notifications(db, 'security.alert', alert)

    def update_host_metadata(self, db, host, event, received):
        fields = ('agent_version','platform','hostname','queue_depth','queue_capacity','collection_paused')
        metadata = {field: getattr(event, field) for field in fields if getattr(event, field) is not None}
        if metadata:
            current = db.execute('SELECT metadata FROM enrolled_hosts WHERE host=?', (host,)).fetchone()
            metadata = {**(json.loads(current['metadata']) if current else {}), **metadata}
            db.execute('UPDATE enrolled_hosts SET metadata=?,last_seen=? WHERE host=?',
                       (json.dumps(metadata),received,host))
        else:
            db.execute('UPDATE enrolled_hosts SET last_seen=? WHERE host=?', (received,host))

    def incident_list(self):
        with self.connect() as db:
            result=[]
            for row in db.execute('SELECT * FROM incidents ORDER BY updated DESC LIMIT 200'):
                item=dict(row)
                item['alert_ids']=[r[0] for r in db.execute('SELECT alert_id FROM incident_alerts WHERE incident_id=?',(row['id'],))]
                result.append(item)
            return result
