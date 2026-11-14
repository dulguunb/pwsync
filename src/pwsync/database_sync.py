"""Bidirectional copy between two KeePass databases, without merging entries."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .keepass import Keepass, KeepassError
from .model import Entry


@dataclass
class DatabasePlan:
    """Entries to append to each database; originals are never removed."""

    add_to_a: list[Entry] = field(default_factory=list)
    add_to_b: list[Entry] = field(default_factory=list)
    identical_pairs: int = 0
    conflicts: int = 0


@dataclass
class DatabaseSyncResult:
    added_to_a: int = 0
    added_to_b: int = 0
    backups: tuple[Path, ...] = ()


def _fingerprint(path: Path) -> tuple[str, int]:
    """Use the same content+mtime fingerprint as the Keepass wrapper."""
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), path.stat().st_mtime_ns


def _signature(entry: Entry) -> tuple[object, ...]:
    """All copied content except the identifier and modification timestamp."""
    return (
        entry.title,
        entry.username,
        entry.password,
        entry.url,
        entry.notes,
        entry.totp,
        entry.folder,
        entry.custom,
    )


def _identity(entry: Entry) -> tuple[str, str]:
    """Case/whitespace normalized title+username identifies an overlap."""
    return entry.match_key()


def plan_database_sync(a: Keepass, b: Keepass) -> DatabasePlan:
    """Plan a union. Every distinct version for an identity is kept in both.

    ``conflicts`` counts identities present in both databases with different
    sets of content versions. For each normalized (title, username), compare
    match duplicate multiplicities one-to-one. A signature present N times in
    one database and M times in the other is copied only to make both counts
    equal to max(N, M). Different versions are treated as different entries and
    copied in both directions; no fields are merged or overwritten.
    """
    entries_a = list(a.entries().values())
    entries_b = list(b.entries().values())
    signatures_a: dict[tuple[str, str], dict[tuple[object, ...], int]] = {}
    signatures_b: dict[tuple[str, str], dict[tuple[object, ...], int]] = {}
    samples_a: dict[tuple[tuple[str, str], tuple[object, ...]], Entry] = {}
    samples_b: dict[tuple[tuple[str, str], tuple[object, ...]], Entry] = {}

    for entries, counts, samples in (
        (entries_a, signatures_a, samples_a),
        (entries_b, signatures_b, samples_b),
    ):
        for entry in entries:
            identity = _identity(entry)
            signature = _signature(entry)
            versions = counts.setdefault(identity, {})
            versions[signature] = versions.get(signature, 0) + 1
            samples[(identity, signature)] = entry

    plan = DatabasePlan()
    for identity in signatures_a.keys() | signatures_b.keys():
        versions_a = signatures_a.get(identity, {})
        versions_b = signatures_b.get(identity, {})
        if versions_a and versions_b and versions_a.keys() != versions_b.keys():
            plan.conflicts += 1
        a_versions = signatures_a.get(identity, {})
        b_versions = signatures_b.get(identity, {})
        for signature in a_versions.keys() | b_versions.keys():
            count_a = a_versions.get(signature, 0)
            count_b = b_versions.get(signature, 0)
            copies = abs(count_a - count_b)
            if count_a == count_b:
                plan.identical_pairs += count_a
                continue
            if count_a and count_b:
                plan.identical_pairs += min(count_a, count_b)
            target = plan.add_to_b if count_a > count_b else plan.add_to_a
            sample = samples_a.get((identity, signature)) or samples_b[(identity, signature)]
            target.extend(sample for _ in range(copies))
    return plan


def _backup(path: Path, backup_dir: Path, label: str) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = backup_dir / f"{stamp}-{label}-{path.name}"
    fd, temporary = tempfile.mkstemp(prefix=".pwsync-", dir=backup_dir)
    os.close(fd)
    temp_path = Path(temporary)
    try:
        shutil.copy2(path, temp_path)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, target)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return target


def apply_database_sync(a: Keepass, b: Keepass, plan: DatabasePlan,
                        backup_dir: str | Path) -> DatabaseSyncResult:
    """Append planned entries to both DBs, backing up before any modifications.

    Refuses to write if either file changed since it was opened. If either save
    fails after the first one committed, backups remain available for recovery.
    """
    if not plan.add_to_a and not plan.add_to_b:
        return DatabaseSyncResult()
    if a.path.resolve() == b.path.resolve():
        raise KeepassError("the two KeePass database paths must be different")
    if _fingerprint(a.path) != a._fingerprint or _fingerprint(b.path) != b._fingerprint:
        raise KeepassError("a KeePass database changed on disk since it was opened; refusing to overwrite")

    backup_dir = Path(backup_dir).expanduser()
    backups = (
        _backup(a.path, backup_dir, "a"),
        _backup(b.path, backup_dir, "b"),
    )
    for entry in plan.add_to_a:
        a.create(entry)
    for entry in plan.add_to_b:
        b.create(entry)
    # Recheck both before the first atomic save to avoid overwriting external edits.
    if _fingerprint(a.path) != a._fingerprint or _fingerprint(b.path) != b._fingerprint:
        raise KeepassError("a KeePass database changed during sync; refusing to overwrite")
    # Save both files after any additions, even if one side was only a source.
    a.save(force=True)
    b.save(force=True)
    return DatabaseSyncResult(len(plan.add_to_a), len(plan.add_to_b), backups)
