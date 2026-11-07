"""KeePassXC (.kdbx) access through pykeepass."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from uuid import UUID

from pykeepass import PyKeePass

from .model import Entry, as_utc


class KeepassError(RuntimeError):
    """A failed or impossible KeePass operation."""


def _read(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), path.stat().st_mtime_ns


def entry_from_kp(entry, folder: str) -> Entry:
    custom = tuple(
        sorted((k, v) for k, v in entry.custom_properties.items() if k.lower() != "otp")
    )
    return Entry(
        title=entry.title or "",
        username=entry.username or "",
        password=entry.password or "",
        url=entry.url or "",
        notes=entry.notes or "",
        totp=entry.otp or "",
        folder=folder,
        custom=custom,
        updated=as_utc(entry.mtime),
        key=str(entry.uuid),
    )


class Keepass:
    """A live KeePass database, with writes buffered until :meth:`save`."""

    def __init__(self, path: str | Path, password: str, root_group: str = "",
                 keyfile: str | Path | None = None, separator: str = "/"):
        self.path = Path(path)
        self.root_group = root_group
        self.separator = separator
        self.dirty = False
        if not self.path.is_file():
            raise KeepassError(f"KeePass database not found: {self.path}")
        self._fingerprint = _read(self.path)
        try:
            self.kp = PyKeePass(
                str(self.path),
                password=password,
                keyfile=str(keyfile) if keyfile else None,
            )
        except Exception as exc:  # pykeepass raises assorted errors for bad credentials
            raise KeepassError(f"cannot open {self.path}: {exc}") from exc
        self.scope = self._find_scope()

    # -- groups -------------------------------------------------------------
    @property
    def _parts(self) -> list[str]:
        return [p for p in self.root_group.split(self.separator) if p]

    def _find_scope(self):
        group = self.kp.root_group
        for part in self._parts:
            group = next((g for g in group.subgroups if g.name == part), None)
            if group is None:
                return None
        return group

    def ensure_scope(self):
        if self.scope is not None:
            return self.scope
        group = self.kp.root_group
        for part in self._parts:
            group = next((g for g in group.subgroups if g.name == part), None) or self.kp.add_group(group, part)
            self.dirty = True
        self.scope = group
        return group

    def ensure_folder_group(self, folder: str):
        group = self.ensure_scope()
        if not folder:
            return group
        for part in folder.split(self.separator):
            if not part:
                continue
            group = next((g for g in group.subgroups if g.name == part), None) or self.kp.add_group(group, part)
            self.dirty = True
        return group

    # -- reads --------------------------------------------------------------
    def _relative_folder(self, entry, scope) -> str | None:
        parts: list[str] = []
        group = entry.group
        while group is not None and group.uuid != scope.uuid:
            if group.is_root_group:
                return None
            parts.insert(0, group.name or "")
            group = group.parentgroup
        if group is None:
            return None
        return self.separator.join(p for p in parts if p)

    def entries(self) -> dict[str, Entry]:
        scope = self._find_scope()
        if scope is None:
            return {}
        out: dict[str, Entry] = {}
        for kp_entry in self.kp.entries:
            folder = self._relative_folder(kp_entry, scope)
            if folder is None:
                continue
            out[str(kp_entry.uuid)] = entry_from_kp(kp_entry, folder)
        return out

    def _find(self, uuid_str: str):
        kp_entry = self.kp.find_entries(uuid=UUID(uuid_str), first=True)
        if kp_entry is None:
            raise KeepassError(f"entry {uuid_str} not found")
        return kp_entry

    # -- writes -------------------------------------------------------------
    def _apply_custom(self, kp_entry, entry: Entry) -> None:
        existing = {
            k: v for k, v in kp_entry.custom_properties.items() if k.lower() != "otp"
        }
        desired = entry.custom_dict()
        for name in list(existing):
            if name not in desired:
                kp_entry.delete_custom_property(name)
        for name, value in desired.items():
            if existing.get(name) != value:
                kp_entry.set_custom_property(name, value, protect=False)

    def create(self, entry: Entry) -> str:
        group = self.ensure_folder_group(entry.folder)
        kp_entry = self.kp.add_entry(
            group,
            entry.title,
            entry.username,
            entry.password,
            url=entry.url or None,
            notes=entry.notes or None,
            otp=entry.totp or None,
        )
        self._apply_custom(kp_entry, entry)
        self.dirty = True
        return str(kp_entry.uuid)

    def update(self, uuid_str: str, entry: Entry) -> None:
        kp_entry = self._find(uuid_str)
        kp_entry.title = entry.title
        kp_entry.username = entry.username
        kp_entry.password = entry.password
        kp_entry.url = entry.url or ""
        kp_entry.notes = entry.notes or ""
        kp_entry.otp = entry.totp or ""
        self._apply_custom(kp_entry, entry)
        target = self.ensure_folder_group(entry.folder)
        if kp_entry.group.uuid != target.uuid:
            self.kp.move_entry(kp_entry, target)
        self.dirty = True

    def delete(self, uuid_str: str) -> None:
        self._find(uuid_str).delete()
        self.dirty = True

    def save(self) -> bool:
        """Atomically persist pending writes; refuses if the file changed."""
        if not self.dirty:
            return False
        if _read(self.path) != self._fingerprint:
            raise KeepassError(
                "the KeePass database changed on disk during the sync; "
                "refusing to overwrite it"
            )
        tmp = self.path.with_name(self.path.name + ".pwsync-tmp")
        try:
            self.kp.save(str(tmp))
            os.chmod(tmp, self.path.stat().st_mode & 0o777)
            os.replace(tmp, self.path)
        finally:
            if tmp.exists():
                tmp.unlink()
        self._fingerprint = _read(self.path)
        self.dirty = False
        return True
