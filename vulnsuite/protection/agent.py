"""Host agent with durable bounded delivery, native event inputs and file baseline."""
import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .models import Event
from .response import block_ip
from .sensors import malware_events, parse_modsecurity, process_events
from .telemetry import parse_linux_audit, parse_windows_event

LOG = logging.getLogger(__name__)
AGENT_VERSION = "0.4.0"
SSH = re.compile(r"(?:Failed (?:password|publickey) for (?:invalid user )?(?P<failed>\S+)|"
                 r"Accepted (?:password|publickey) for (?P<accepted>\S+)) from (?P<ip>\S+)")


def parse_line(line: str, source: str) -> dict | None:
    """Raw messages, URLs, passwords and authorization headers never leave the host."""
    if source == "ssh":
        match = SSH.search(line)
        if not match:
            return None
        try:
            ip = str(ipaddress.ip_address(match["ip"]))
        except ValueError:
            return None
        return {"kind": "auth_failure" if match["failed"] else "auth_success",
                "source_ip": ip, "protocol": "ssh", "user": (match["failed"] or match["accepted"])[:128]}
    if source == "api":
        try:
            row = json.loads(line)
            if int(row["status"]) not in (401, 403):
                return None
            return {"kind": "api_denied", "source_ip": str(ipaddress.ip_address(row["remote_addr"]))}
        except (ValueError, KeyError, TypeError):
            return None
    if source == "modsecurity":
        return parse_modsecurity(line)
    if source == "linux_audit":
        return parse_linux_audit(line)
    if source == "windows_event":
        return parse_windows_event(line)
    raise ValueError("unknown log source")


def event(fields: dict) -> dict:
    return Event(**fields).model_dump(mode="json")


def save_state(path: Path, state: dict):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def fingerprint(path: str) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            raise ValueError("monitored files must be regular files up to 16 MiB")
        digest = hashlib.sha256()
        total = 0
        while chunk := stream.read(65536):
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise ValueError("monitored file grew beyond 16 MiB")
            digest.update(chunk)
        return f"{info.st_mode}:{info.st_uid}:{info.st_gid}:{digest.hexdigest()}"


def sensor_event(state, outbox, sensor, status, detail):
    previous = state.setdefault("sensor_states", {}).get(sensor, {})
    now = time.time()
    if (previous.get("status"), previous.get("detail")) != (status, detail) or now - previous.get("sent", 0) >= 60:
        if len(outbox) < state.get("queue_capacity", 5000):
            outbox.append(event({"kind": "sensor_status", "sensor": sensor,
                                 "sensor_status": status, "sensor_detail": detail}))
            state["sensor_states"][sensor] = {"status": status, "detail": detail, "sent": now}


def collect_log(source, offsets, capacity):
    path = source["path"]
    events = []
    partial = False
    with open(path, "rb") as stream:
        info = os.fstat(stream.fileno())
        identity = f"{info.st_dev}:{info.st_ino}"
        old = offsets.get(path)
        if old is None:
            offsets[path] = {"identity": identity, "position": 0 if source.get("read_from_start") else info.st_size}
            old = offsets[path]
        same = old["identity"] == identity and old["position"] <= info.st_size
        position = old["position"] if same else 0
        skipping = old.get("skipping", False) if same else False
        stream.seek(position)
        for _ in range(min(1000, capacity)):
            start = stream.tell()
            line = stream.readline(65537)
            if not line:
                break
            if skipping or len(line) > 65536:
                partial = True
                skipping = not line.endswith(b"\n")
                continue
            if not line.endswith(b"\n"):
                stream.seek(start)
                break
            try:
                parsed = parse_line(line.decode("utf-8", errors="replace"), source["kind"])
                if parsed:
                    events.append(event(parsed))
            except ValueError:
                partial = True
        offsets[path] = {"identity": identity, "position": stream.tell(), "skipping": skipping}
    return events, "partial" if partial else "ok", "input_error" if partial else "collected"


def queue_capacity(config):
    capacity = config.get("queue_capacity", 5000)
    if isinstance(capacity, bool) or not isinstance(capacity, int) or not 100 <= capacity <= 1000000:
        raise ValueError("queue_capacity must be an integer from 100 to 1000000")
    return capacity


def heartbeat(config, state):
    return event({"kind": "heartbeat", "agent_version": AGENT_VERSION,
                  "platform": "windows" if os.name == "nt" else "linux",
                  "hostname": socket.gethostname()[:255],
                  "queue_depth": len(state.get("outbox", [])), "queue_capacity": queue_capacity(config),
                  "collection_paused": state.get("collection_paused", False)})


def collect(config: dict, state: dict) -> None:
    outbox = state.setdefault("outbox", [])
    capacity = state["queue_capacity"] = queue_capacity(config)
    # Reserve space for health; no data event is evicted to make room.
    limit = capacity - 10
    state["collection_paused"] = len(outbox) >= limit
    if state["collection_paused"]:
        LOG.error("Outbox capacity reached; collection paused, retained events awaiting delivery")
        return
    if state.get("delivery", {}).get("status") == "ok":
        sensor_event(state, outbox, "delivery", "ok", "collected")
    offsets = state.setdefault("offsets", {})
    baseline = state.setdefault("files", {})
    if state.get('response_cleanup'):
        cleanup = state['response_cleanup']
        sensor_event(state, outbox, 'response', cleanup['status'], cleanup['detail'])
    log_health = {}
    for source in config.get("logs", []):
        if len(outbox) >= limit:
            LOG.error("Outbox full; log collection paused until delivery recovers")
            break
        sensor = "waf" if source["kind"] == "modsecurity" else "telemetry" if source["kind"] in ("linux_audit", "windows_event") else "logs"
        try:
            items, status, detail = collect_log(source, offsets, limit - len(outbox))
            outbox.extend(items)
        except OSError:
            status, detail = "error", "access_denied"
        # A healthy log cannot hide another inaccessible or malformed log of this sensor.
        previous = log_health.get(sensor)
        if previous is None or status != "ok":
            log_health[sensor] = status, detail
    for sensor, (status, detail) in log_health.items():
        sensor_event(state, outbox, sensor, status, detail)
    files_ok = True
    for path in config.get("watch_files", []):
        if len(outbox) >= limit:
            files_ok = False
            break
        try:
            current = fingerprint(path)
        except (OSError, ValueError):
            files_ok = False
            continue
        if path not in baseline:
            LOG.warning("Enrolling initial file baseline: %s", path)
        elif baseline[path] != current:
            change = "deleted" if current is None else "created" if baseline[path] is None else "modified"
            outbox.append(event({"kind": "file_change", "path": path, "change": change}))
        baseline[path] = current
    if config.get("watch_files"):
        sensor_event(state, outbox, "files", "ok" if files_ok else "partial",
                     "collected" if files_ok else "input_error")
    if config.get("windows_eventlog", {}).get("enabled") and len(outbox) < limit:
        from .windows_agent import collect_windows
        items, status, detail = collect_windows(config["windows_eventlog"], state, min(500, limit - len(outbox)))
        outbox.extend(event(item) for item in items)
        sensor_event(state, outbox, "telemetry", status, detail)
    if config.get("process_monitor", {}).get("enabled") and len(outbox) < limit:
        try:
            items, status, detail = process_events(config["process_monitor"], state,
                                                  max_events=min(500, limit - len(outbox)))
            outbox.extend(event(item) for item in items)
        except (OSError, ValueError):
            status, detail = "error", "access_denied"
        sensor_event(state, outbox, "process", status, detail)
    if config.get("malware", {}).get("enabled") and len(outbox) < limit - 20:
        items, status, detail = malware_events(config["malware"], state)
        outbox.extend(event(item) for item in items)
        if status is None:
            previous = state.get("sensor_states", {}).get("malware", {})
            status, detail = previous.get("status", "partial"), previous.get("detail", "input_error")
        sensor_event(state, outbox, "malware", status, detail)
    state["collection_paused"] = len(outbox) >= limit
    # Coalesce unsent heartbeats; state still retains every evidence event through outages.
    outbox[:] = [item for item in outbox if item["kind"] != "heartbeat"]
    if len(outbox) < capacity:
        outbox.append(heartbeat(config, state))


def respond(command: dict, config: dict) -> dict:
    # The original IP-block endpoint remains nftables-only. Windows containment
    # uses the separately approved, platform-bound playbook workflow.
    if os.name == 'nt':
        return {"status": "failed", "detail": "policy_denied"}
    if not config.get("allow_response", False) or not config.get("protected_networks"):
        return {"status": "failed", "detail": "policy_denied"}
    if time.time() - command["created"] > 300 or command["created"] > time.time() + 30:
        return {"status": "failed", "detail": "policy_denied"}
    try:
        block_ip(command["ip"], command["duration"], config["protected_networks"],
                 config.get("permitted_networks", []))
    except ValueError:
        return {"status": "failed", "detail": "policy_denied"}
    except (OSError, subprocess.SubprocessError):
        return {"status": "failed", "detail": "firewall_error"}
    return {"status": "applied", "detail": "blocked"}


def cycle(config: dict, state: dict, path: Path, client):
    if config.get('response_policy') or state.get('playbook_receipts'):
        from .response_agent import cleanup_playbooks
        cleanup_playbooks(config, state, path)
    # Commit offsets, baseline and outbox together before network activity.
    collect(config, state)
    save_state(path, state)
    try:
        # A full queue or invalid retained batch must not hide live delivery/agent health.
        # Keep one durable health envelope outside the evidence capacity.
        recovering = bool(state.get("collection_paused") or state.get("delivery", {}).get("status") == "error")
        if recovering:
            detail = "backpressure" if state.get("collection_paused") else "delivery_error"
            state["health_outbox"] = [heartbeat(config, state), event({"kind": "sensor_status",
                "sensor": "delivery", "sensor_status": "partial", "sensor_detail": detail})]
            save_state(path, state)
            deliver(client, state["health_outbox"])
            state.pop("health_outbox", None)
            save_state(path, state)
        while state["outbox"]:
            batch = state["outbox"][:40]
            deliver(client, batch)
            del state["outbox"][:len(batch)]
            state["delivery"] = {"status": "ok", "last_success": time.time(), "failures": 0}
            save_state(path, state)
        if recovering:
            state["collection_paused"] = False
            state["health_outbox"] = [heartbeat(config, state), event({"kind": "sensor_status",
                "sensor": "delivery", "sensor_status": "ok", "sensor_detail": "collected"})]
            save_state(path, state)
            deliver(client, state["health_outbox"])
            state.pop("health_outbox", None)
            state["delivery"] = {"status": "ok", "last_success": time.time(), "failures": 0}
            save_state(path, state)
    except (httpx.HTTPError, ValueError) as exc:
        previous = state.get("delivery", {})
        state["delivery"] = {"status": "error", "last_failure": time.time(),
                             "last_success": previous.get("last_success"),
                             "failures": previous.get("failures", 0) + 1,
                             "detail": "ack_error" if isinstance(exc, ValueError) else "delivery_error"}
        save_state(path, state)
        raise
    result = client.get("/v1/commands")
    result.raise_for_status()
    receipts = state.setdefault("receipts", {})
    for command in result.json()["commands"]:
        key = str(command["id"])
        if key not in receipts:
            # Record an uncertain attempt before mutation: never extend a block after a crash.
            receipts[key] = {"status": "failed", "detail": "firewall_error"}
            save_state(path, state)
            receipts[key] = respond(command, config)
            save_state(path, state)
        ack = client.post(f"/v1/commands/{command['id']}/receipt", json=receipts[key])
        ack.raise_for_status()
    # Keep recent retry receipts bounded; commands expire on the server after five minutes.
    if len(receipts) > 1000:
        state["receipts"] = dict(sorted(receipts.items(), key=lambda p: int(p[0]))[-1000:])
    save_state(path, state)
    if config.get("response_policy", {}).get("enabled") or state.get("playbook_receipts"):
        from .response_agent import poll_playbooks
        poll_playbooks(config, state, path, client)


def deliver(client, batch):
    result = client.post("/v1/events", json={"events": batch})
    result.raise_for_status()
    payload = result.json()
    accepted = payload.get("accepted") if isinstance(payload, dict) else None
    if type(accepted) is not int or accepted != len(batch):
        raise ValueError("server did not acknowledge the entire batch; retaining for retry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    config = json.loads(Path(args.config).read_text())
    parsed = urlparse(config["server_url"])
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1")):
        raise ValueError("HTTPS required except on loopback")
    if len(config["token"]) < 32:
        raise ValueError("agent token must have at least 32 characters")
    from .sensors import indicators
    indicators(config.get("process_monitor", {}))
    indicators(config.get("malware", {}))
    queue_capacity(config)
    # Only one agent can own the offsets/outbox or execute responses on this host.
    path = Path(config["state_path"])
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path.with_suffix(".lock"), "a+b") as lock:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            lock.write(b"\0")
            lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with httpx.Client(base_url=config["server_url"].rstrip("/"),
                          headers={"Authorization": f"Bearer {config['token']}"},
                          timeout=15, follow_redirects=False, trust_env=False) as client:
            while True:
                try:
                    # Reload only committed state after errors, preventing offset/data loss.
                    state = json.loads(path.read_text()) if path.exists() else {}
                    cycle(config, state, path, client)
                except Exception as exc:
                    LOG.error("Agent cycle failed (%s); retrying", type(exc).__name__)
                time.sleep(max(5, min(int(config.get("poll_seconds", 10)), 60)))


if __name__ == "__main__":
    main()
