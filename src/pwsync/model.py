"""Vault-neutral entry model shared by both sides of the sync."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone

CORE_FIELDS = ("title", "username", "password", "url", "notes", "totp", "folder")


def as_utc(value: datetime | None) -> datetime | None:
    """Return ``value`` in UTC, treating naive timestamps as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def norm(value: str) -> str:
    """Collapse whitespace and casefold, for matching entry titles."""
    return " ".join((value or "").split()).casefold()


@dataclass(frozen=True)
class Entry:
    """One login entry as the sync sees it, independent of either vault."""

    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp: str = ""
    folder: str = ""
    custom: tuple[tuple[str, str], ...] = ()
    updated: datetime | None = None
    key: str = ""  # vault-local id: Bitwarden item id or KeePass UUID

    def core(self) -> dict[str, object]:
        return {
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "totp": self.totp,
            "folder": self.folder,
            "custom": dict(self.custom),
        }

    def content_hash(self) -> str:
        payload = json.dumps(self.core(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def custom_dict(self) -> dict[str, str]:
        return dict(self.custom)

    def with_changes(self, **changes: object) -> "Entry":
        return replace(self, **changes)

    def match_key(self) -> tuple[str, str]:
        """Heuristic identity used only to *propose* links between vaults."""
        return (norm(self.title), norm(self.username))

    def diff(self, other: "Entry") -> list[str]:
        """Field labels that differ from ``other`` (never the values)."""
        changed = [f for f in CORE_FIELDS if getattr(self, f) != getattr(other, f)]
        mine, theirs = self.custom_dict(), other.custom_dict()
        for name in sorted(set(mine) | set(theirs)):
            if mine.get(name) != theirs.get(name):
                changed.append(f"custom:{name}")
        return changed
