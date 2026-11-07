"""Persistent link table and tombstones, stored as a private JSON document."""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

VERSION = 1
SIDES = ("bitwarden", "keepassxc")


class StateError(RuntimeError):
    """A corrupt, incompatible or locked state file."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Link:
    bw_id: str
    kp_uuid: str
    hash: str
    synced_at: str

    @classmethod
    def from_json(cls, bw_id: str, raw: dict) -> "Link":
        return cls(
            bw_id=bw_id,
            kp_uuid=str(raw["kp_uuid"]),
            hash=str(raw["hash"]),
            synced_at=str(raw.get("synced_at", "")),
        )

    def to_json(self) -> dict:
        return {"kp_uuid": self.kp_uuid, "hash": self.hash, "synced_at": self.synced_at}


class State:
    """Link table keyed by Bitwarden item id, plus per-side tombstones."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.links: dict[str, Link] = {}
        self.tombstones: dict[str, dict[str, dict]] = {side: {} for side in SIDES}
        self._lock = None

    @classmethod
    def open(cls, path: str | Path) -> "State":
        state = cls(path)
        state._acquire()
        state.load()
        return state

    def _acquire(self) -> None:
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
            # 0600 from the moment it exists, so no window with looser mode.
            fd = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.chmod(lock_path, 0o600)
            self._lock = os.fdopen(fd, "w")
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._close_lock()
            raise StateError(f"another pwsync run holds the lock: {lock_path}") from exc
        except OSError as exc:
            self._close_lock()
            raise StateError(
                f"cannot use the state file {self.path}: {exc.strerror or exc}. "
                f"Point [sync] state_file at a writable path."
            ) from exc

    def _close_lock(self) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise StateError(f"{self.path} is not valid JSON: {exc}") from exc
        if data.get("version") != VERSION:
            raise StateError(
                f"{self.path} has version {data.get('version')!r}, expected {VERSION}"
            )
        self.links = {
            str(bw_id): Link.from_json(str(bw_id), raw)
            for bw_id, raw in (data.get("links") or {}).items()
        }
        tombstones = data.get("tombstones") or {}
        self.tombstones = {
            side: {str(k): dict(v) for k, v in (tombstones.get(side) or {}).items()}
            for side in SIDES
        }

    def save(self) -> None:
        payload = json.dumps(
            {
                "version": VERSION,
                "links": {bw_id: link.to_json() for bw_id, link in self.links.items()},
                "tombstones": self.tombstones,
            },
            indent=2,
            sort_keys=True,
        )
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)

    # -- link table ---------------------------------------------------------
    def link(self, bw_id: str, kp_uuid: str, content_hash: str) -> Link:
        link = Link(bw_id=bw_id, kp_uuid=kp_uuid, hash=content_hash, synced_at=_now())
        self.links[bw_id] = link
        self.clear_tombstone("bitwarden", bw_id)
        self.clear_tombstone("keepassxc", kp_uuid)
        return link

    def unlink(self, bw_id: str) -> None:
        self.links.pop(bw_id, None)

    def link_for_kp(self, kp_uuid: str) -> Link | None:
        return next((l for l in self.links.values() if l.kp_uuid == kp_uuid), None)

    # -- tombstones ---------------------------------------------------------
    def tombstone(self, side: str, key: str) -> None:
        self.tombstones[side][key] = {"at": _now()}

    def clear_tombstone(self, side: str, key: str) -> None:
        self.tombstones[side].pop(key, None)

    def is_tombstoned(self, side: str, key: str) -> bool:
        return key in self.tombstones[side]

    def close(self) -> None:
        if self._lock is not None:
            fcntl.flock(self._lock, fcntl.LOCK_UN)
            self._lock.close()
            self._lock = None
