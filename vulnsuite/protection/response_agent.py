"""Approved local playbooks, with independent host policy and durable receipts."""
from __future__ import annotations

import math
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID

from .playbooks import Quarantine, apply_isolation, release_isolation


def native_platform():
    if sys.platform == 'win32':
        return 'windows'
    if sys.platform.startswith('linux'):
        return 'linux'
    return None


def execute_playbook(config: dict, command: dict) -> dict:
    policy = config.get("response_policy", {})
    try:
        if not isinstance(command,dict) or not isinstance(policy,dict):
            raise ValueError('invalid local response data')
        action, plan = command["action"], command["plan"]
        if not isinstance(plan,dict):
            raise ValueError('invalid response plan')
        platform = native_platform()
        # Legacy plans are Linux-only. Windows requires explicit policy and plan
        # opt-in; a server-provided platform cannot change the actual host OS.
        if (policy.get('enabled') is not True or platform is None
                or policy.get('platform','linux') != platform
                or plan.get('platform','linux') != platform
                or action not in policy.get('allowed_actions', [])):
            raise ValueError('response platform or action outside local policy')
        UUID(command["id"])
        UUID(plan["request_id"])
        deadline = plan["expires_at"]
        if type(deadline) not in (float, int) or not math.isfinite(deadline) or not time.time() < deadline <= time.time() + 3600:
            raise ValueError("dispatch deadline expired or invalid")
        if action in ("quarantine_file", "isolate_host", "terminate_process") and UUID(plan["request_id"]) != UUID(command["id"]):
            raise ValueError("job identifier mismatch")
        if platform == 'windows':
            from .windows_quarantine import WindowsQuarantine
            from .windows_isolation import apply_windows_isolation, release_windows_isolation
            quarantine_class = WindowsQuarantine
        else:
            quarantine_class = Quarantine
        if action == "quarantine_file":
            result = quarantine_class(policy["quarantine"]).quarantine(
                plan["path"], plan["sha256"], plan["request_id"])
        elif action == "restore_file":
            result = quarantine_class(policy["quarantine"]).restore(plan["request_id"])
        elif action == "isolate_host":
            result = (apply_windows_isolation(policy['isolation'], plan) if platform == 'windows'
                      else apply_isolation(policy["isolation"], plan))
        elif action == "release_host":
            result = (release_windows_isolation(policy['isolation'], plan['request_id']) if platform == 'windows'
                      else release_isolation(plan["request_id"]))
        elif action == "terminate_process":
            # Not reversible: the host re-verifies the process identity before signalling.
            if platform == 'windows':
                from .windows_process import terminate_windows_process
                result = terminate_windows_process(policy.get('termination', {}), plan)
            else:
                from .process_response import terminate_process
                result = terminate_process(policy.get('termination', {}), plan)
        else:
            raise ValueError("unsupported local action")
        return {"status": result["status"], "detail": result["detail"], "result": {**result, 'platform': platform}}
    except (ValueError, KeyError, TypeError):
        return {"status": "failed", "detail": "policy_denied", "result": {}}
    except (OSError, subprocess.SubprocessError, ImportError):
        return {"status": "failed", "detail": "execution_failed", "result": {}}


def cleanup_playbooks(config: dict, state: dict, path: Path) -> None:
    """Local expiry recovery runs even when the network or response policy is down."""
    from .agent import save_state
    receipts = state.setdefault("playbook_receipts", {})
    policy = config.get('response_policy', {})
    platform = native_platform()
    if (platform == 'windows' and policy.get('platform') == 'windows' and policy.get('isolation')
            and (policy.get('enabled') or receipts or state.get('windows_cleanup_required'))):
        try:
            from .windows_isolation import cleanup_expired
            cleanup_expired(policy['isolation'])
            state.pop('windows_cleanup_error', None)
            state['response_cleanup'] = {'status':'ok', 'detail':'collected'}
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, ImportError):
            state['windows_cleanup_error'] = 'isolation_cleanup_failed'
            state['response_cleanup'] = {'status':'error', 'detail':'execution_error'}
        save_state(path, state)
    # Empty timed sets already stop filtering without this cleanup. Removing their
    # dedicated tables is housekeeping, retried after agent restarts/outages.
    for record in receipts.values():
        result = record.get("receipt", {}).get("result", {})
        if (result.get("detail") == "isolated" and result.get("expires_at", 0) <= time.time()
                and not record.get("isolation_cleaned")):
            try:
                if platform != result.get('platform','linux'):
                    raise ValueError('saved isolation belongs to a different platform')
                if platform == 'windows':
                    from .windows_isolation import release_windows_isolation
                    release_windows_isolation(policy['isolation'], result['request_id'])
                elif platform == 'linux':
                    release_isolation(result["request_id"])
                else:
                    raise ValueError('unsupported platform')
                record["isolation_cleaned"] = True
                record.pop("cleanup_error", None)
            except (OSError, subprocess.SubprocessError, ValueError, KeyError, ImportError):
                record["cleanup_error"] = "isolation_cleanup_failed"
                state['response_cleanup'] = {'status':'error', 'detail':'execution_error'}
            save_state(path, state)


def poll_playbooks(config: dict, state: dict, path: Path, client) -> None:
    """Fetch approved host-scoped commands; persist receipts before acknowledging."""
    from .agent import save_state
    cleanup_playbooks(config, state, path)
    receipts = state.setdefault("playbook_receipts", {})
    # Flush pending acknowledgements even if command listing is temporarily down.
    for identifier, record in list(receipts.items()):
        if not record.get("acknowledged"):
            response = client.post(f"/v1/playbooks/{identifier}/receipt", json=record["receipt"])
            response.raise_for_status()
            record["acknowledged"] = True
            save_state(path, state)
    # Disabling new response must not suppress receipts for an earlier attempt.
    if not config.get("response_policy", {}).get("enabled"):
        return
    response = client.get("/v1/playbooks/commands")
    response.raise_for_status()
    commands = response.json()["commands"]
    if not isinstance(commands, list) or len(commands) > 100:
        raise ValueError("invalid playbook batch")
    for command in commands:
        identifier = command["id"]
        UUID(identifier)
        if identifier not in receipts:
            # Commit uncertainty BEFORE native mutation. A process crash then
            # reports an uncertain failure instead of replaying a privileged action.
            # A separately approved rollback can inspect the host's native journal.
            receipts[identifier] = {'receipt': {'status':'failed', 'detail':'execution_failed',
                                               'result':{'execution_uncertain':True}},
                                    'at': time.time(), 'acknowledged':False, 'uncertain':True}
            save_state(path, state)
            result = execute_playbook(config, command)
            receipts[identifier] = {"receipt": result, "at": time.time(),
                                    "acknowledged": False, 'uncertain':False}
            save_state(path, state)
        response = client.post(f"/v1/playbooks/{identifier}/receipt",
                               json=receipts[identifier]["receipt"])
        response.raise_for_status()
        receipts[identifier]["acknowledged"] = True
        save_state(path, state)
    # Keep pending records and at least seven days of replay protection. The
    # service cannot return expired jobs; quarantine manifests persist separately.
    if len(receipts) > 2000:
        for identifier, record in sorted(receipts.items(), key=lambda item: item[1]["at"]):
            if record.get("acknowledged") and record["at"] < time.time() - 7 * 86400:
                del receipts[identifier]
                if len(receipts) <= 2000:
                    break
        save_state(path, state)
