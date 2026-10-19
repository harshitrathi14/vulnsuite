"""Ransomware early-warning sensor (Linux and Windows, polling, read-only).

Three independent signals, all computed from directory metadata and bounded
file reads; the agent never creates, writes or deletes files:

- canary files provisioned by the operator (`canary_files`): any change to
  their size, mtime or content hash, or their disappearance, is a signal;
- mass change in watched directories (`watch_dirs`): the number of files
  renamed, rewritten or deleted since the previous poll compared with a
  threshold, with the most common new extensions reported;
- high-entropy rewrites: a bounded sample of files modified since the previous
  poll whose first 64 KiB has near-random byte entropy.

Encryption is detected after it starts, at the next poll; the signal is for
containment and investigation, not prevention. Backups decide the outcome.
"""
from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from pathlib import Path

SAMPLE_BYTES = 64 * 1024
MAX_ENTRIES = 5000
MAX_DIRS = 16
MAX_CANARIES = 64
ENTROPY_SAMPLES = 8
HIGH_ENTROPY = 7.5


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _read_head(path: str, limit: int = SAMPLE_BYTES) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        return stream.read(limit)


def _canary_fingerprint(path: str) -> str | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        return "unsupported"
    digest = hashlib.sha256(_read_head(path, 1024 * 1024)).hexdigest()
    return f"{info.st_size}:{info.st_mtime_ns}:{digest}"


def validate_config(config: dict) -> dict:
    canaries = config.get("canary_files", [])
    dirs = config.get("watch_dirs", [])
    if not isinstance(canaries, list) or len(canaries) > MAX_CANARIES or any(
            not isinstance(p, str) or not p or len(p) > 1024 for p in canaries):
        raise ValueError("canary_files must be up to 64 absolute paths")
    if not isinstance(dirs, list) or len(dirs) > MAX_DIRS or any(
            not isinstance(p, str) or not p or len(p) > 1024 for p in dirs):
        raise ValueError("watch_dirs must be up to 16 absolute paths")
    for value in canaries + dirs:
        if not (value.startswith("/") or (len(value) > 2 and value[1:3] == ":\\")):
            raise ValueError("ransomware sensor paths must be absolute")
    threshold = config.get("change_threshold", 50)
    if type(threshold) is not int or not 5 <= threshold <= 100000:
        raise ValueError("change_threshold must be 5..100000")
    if not canaries and not dirs:
        raise ValueError("ransomware sensor needs canary_files or watch_dirs")
    return {"canaries": canaries, "dirs": dirs, "threshold": threshold,
            "entropy": config.get("entropy_check", True) is True}


def _listing(directory: str) -> tuple[dict, bool]:
    """name -> (size, mtime_ns, inode) for regular files one level deep; bounded."""
    entries, truncated = {}, False
    try:
        with os.scandir(directory) as scan:
            for entry in scan:
                if len(entries) >= MAX_ENTRIES:
                    truncated = True
                    break
                try:
                    if entry.is_file(follow_symlinks=False):
                        info = entry.stat(follow_symlinks=False)
                        entries[entry.name] = (info.st_size, info.st_mtime_ns, info.st_ino)
                except OSError:
                    truncated = True
    except OSError:
        return {}, True
    return entries, truncated


def ransomware_events(config: dict, state: dict) -> tuple[list[dict], str, str]:
    settings = validate_config(config)
    sensor = state.setdefault("ransomware", {"canaries": {}, "dirs": {}})
    events, partial, detail = [], False, "collected"
    # 1) canaries: operator-provisioned decoy files that nothing legitimate touches.
    for path in settings["canaries"]:
        try:
            current = _canary_fingerprint(path)
        except OSError:
            partial, detail = True, "access_denied"
            continue
        previous = sensor["canaries"].get(path)
        if current == "unsupported":
            partial, detail = True, "input_error"
        elif previous is None and current is None:
            partial, detail = True, "input_error"  # canary never provisioned
        elif previous is not None and current is None:
            events.append({"kind": "ransomware_signal", "signal": "canary_deleted", "path": path})
        elif previous is not None and previous != "unsupported" and current != previous:
            events.append({"kind": "ransomware_signal", "signal": "canary_modified", "path": path})
        sensor["canaries"][path] = current
    # 2) mass change and 3) entropy per watched directory.
    for directory in settings["dirs"]:
        current, truncated = _listing(directory)
        if truncated:
            partial, detail = True, "scan_limit"
        previous = sensor["dirs"].get(directory)
        sensor["dirs"][directory] = current
        if previous is None:
            continue  # baseline poll
        gone = set(previous) - set(current)
        new = set(current) - set(previous)
        modified = {name for name in set(previous) & set(current)
                    if previous[name][:2] != current[name][:2]}
        # A rename shows as one name gone and one new with the same inode.
        inodes_gone = {previous[name][2] for name in gone}
        renamed = {name for name in new if current[name][2] in inodes_gone}
        changes = len(gone) + len(new - renamed) + len(modified) + len(renamed)
        if changes >= settings["threshold"]:
            extensions = Counter(Path(name).suffix.lower() for name in new | modified if Path(name).suffix)
            events.append({"kind": "ransomware_signal", "signal": "mass_change", "path": directory,
                           "change_count": changes,
                           "sample_extensions": [ext for ext, _ in extensions.most_common(8)]})
        if settings["entropy"] and (modified or new):
            sampled, high = 0, 0
            for name in sorted(modified | new)[:ENTROPY_SAMPLES]:
                try:
                    head = _read_head(os.path.join(directory, name))
                except OSError:
                    continue
                if len(head) < 4096:
                    continue
                sampled += 1
                if entropy(head) >= HIGH_ENTROPY:
                    high += 1
            if sampled >= 3 and high >= max(2, (sampled * 3) // 4):
                events.append({"kind": "ransomware_signal", "signal": "high_entropy_rewrite",
                               "path": directory, "change_count": high,
                               "entropy_samples": sampled})
    return events, "partial" if partial else "ok", detail
