"""Strict telemetry and response contracts. Never accept raw log messages or commands."""
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    kind: Literal["auth_failure", "auth_success", "file_change", "api_denied", "heartbeat",
                  "process_alert", "malware_detection", "waf_match", "sensor_status", "process_start",
                  "log_tamper"]
    # Per-agent monotonic counter assigned when the event enters the durable outbox;
    # the service alerts on gaps (lost or removed events) and on resets (replaced state).
    sequence: int | None = Field(default=None, ge=1, le=2**53)
    # Log and audit-trail tampering evidence (host log files, auditd, Windows event log).
    tamper: Literal["truncated", "deleted", "replaced", "written", "attributes",
                    "cleared", "audit_policy_changed", "audit_stopped"] | None = None
    source_ip: str | None = None
    user: str | None = Field(default=None, max_length=128)
    path: str | None = Field(default=None, max_length=1024)
    change: Literal["created", "modified", "deleted"] | None = None

    telemetry_source: Literal["linux_audit", "windows_security", "windows_sysmon"] | None = None
    protocol: Literal["ssh", "rdp", "smb", "winrm", "network"] | None = None
    event_code: int | None = Field(default=None, ge=0, le=100000)
    logon_type: int | None = Field(default=None, ge=0, le=20)
    record_id: str | None = Field(default=None, max_length=128)
    agent_version: str | None = Field(default=None, max_length=64)
    platform: Literal["linux", "windows"] | None = None
    hostname: str | None = Field(default=None, max_length=255)
    queue_depth: int | None = Field(default=None, ge=0, le=1000000)
    queue_capacity: int | None = Field(default=None, ge=1, le=1000000)
    collection_paused: bool | None = None

    pid: int | None = Field(default=None, ge=1, le=2147483647)
    ppid: int | None = Field(default=None, ge=0, le=2147483647)
    start_ticks: int | None = Field(default=None, ge=0)
    executable: str | None = Field(default=None, max_length=1024)
    parent_executable: str | None = Field(default=None, max_length=1024)
    process_rule: Literal["web_server_shell", "writable_directory_execution", "deleted_executable"] | None = None
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    engine: Literal["sha256", "clamav"] | None = None
    signature: str | None = Field(default=None, min_length=1, max_length=128)
    rule_ids: list[StrictInt] = Field(default_factory=list, max_length=32)
    waf_action: Literal["detected", "interrupted", "unknown"] | None = None
    sensor: Literal["process", "malware", "waf", "logs", "files", "telemetry", "delivery", "response"] | None = None
    sensor_status: Literal["ok", "partial", "error"] | None = None
    sensor_detail: Literal["collected", "access_denied", "scanner_error", "scan_limit", "input_error", "backpressure", "delivery_error", "ack_error", "execution_error"] | None = None

    @model_validator(mode="after")
    def required_evidence(self):
        if self.kind in ("auth_failure", "auth_success", "api_denied") and not self.source_ip:
            raise ValueError("source_ip required for access events")
        if self.kind == "file_change" and (not self.path or not self.path.startswith("/") or not self.change):
            raise ValueError("absolute path and change required for file events")
        if self.kind == "process_start" and (not self.pid or not self.executable or not self.telemetry_source):
            raise ValueError("process start evidence required")
        if self.kind == "process_alert" and (not self.pid or self.start_ticks is None
                or not self.executable or not self.process_rule):
            raise ValueError("process evidence required")
        windows_path = (self.platform == "windows" and isinstance(self.path, str)
                        and re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f:]+", self.path)
                        and all(part not in ("", ".", "..") for part in self.path[3:].split("\\")))
        malware_path = windows_path if self.platform == 'windows' else self.path and self.path.startswith('/')
        if self.kind == "malware_detection" and (not malware_path
                or not self.engine or not self.signature or not self.sha256):
            raise ValueError("malware evidence required")
        if self.kind == "waf_match" and (not self.source_ip or not self.rule_ids or not self.waf_action):
            raise ValueError("WAF evidence required")
        if any(isinstance(rule, bool) or not 1 <= rule <= 2147483647 for rule in self.rule_ids):
            raise ValueError("invalid WAF rule ID")
        if self.kind == "sensor_status" and (not self.sensor or not self.sensor_status or not self.sensor_detail):
            raise ValueError("sensor status required")
        if self.kind == "log_tamper" and not self.tamper:
            raise ValueError("tamper evidence required")
        return self

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value)) if value is not None else None

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        return value.astimezone(timezone.utc)


class Batch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[Event] = Field(min_length=1, max_length=200)


class BlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: int = Field(gt=0)
    duration_seconds: int = Field(default=300, ge=60, le=3600)
    reason: str = Field(min_length=10, max_length=500)


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["applied", "failed"]
    # Fixed categories prevent accidentally persisting credentials from command output.
    detail: Literal["blocked", "policy_denied", "firewall_error"]
