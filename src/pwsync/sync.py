"""Plan and apply the two-way sync between Bitwarden and KeePassXC.

The planner is pure: it reads both vaults, compares them against the link
table, and returns a list of actions. :meth:`Syncer.apply` performs them,
saving state only for actions that succeeded.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .bitwarden import Bitwarden, BitwardenError, payload_from_entry
from .config import Config
from .keepass import Keepass, KeepassError
from .model import Entry, as_utc
from .state import Link, State

WRITE_KINDS = {
    "create-bitwarden",
    "create-keepassxc",
    "update-bitwarden",
    "update-keepassxc",
    "delete-bitwarden",
    "delete-keepassxc",
}
ORDER = {
    "create-keepassxc": 0,
    "create-bitwarden": 1,
    "update-keepassxc": 2,
    "update-bitwarden": 3,
    "delete-keepassxc": 4,
    "delete-bitwarden": 5,
    "missing": 6,
    "link": 7,
    "orphan": 8,
    "skip": 9,
}


@dataclass
class Action:
    kind: str
    title: str = ""
    entry: Entry | None = None      # desired content for the receiving side
    current: Entry | None = None    # content being replaced (for the field diff)
    fields: list[str] = field(default_factory=list)
    bw_id: str | None = None
    kp_uuid: str | None = None
    missing_side: str = ""
    note: str = ""

    @property
    def writes(self) -> bool:
        return self.kind in WRITE_KINDS

    def describe_fields(self) -> str:
        return ", ".join(self.fields) if self.fields else ""


@dataclass
class Plan:
    actions: list[Action] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)

    @property
    def writes(self) -> list[Action]:
        return [a for a in self.actions if a.writes]

    @property
    def conflicts(self) -> list[Action]:
        return [a for a in self.actions if a.kind == "conflict"]

    def ordered(self) -> list[Action]:
        return sorted(self.actions, key=lambda a: ORDER.get(a.kind, 99))


@dataclass
class Result:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    tombstoned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def changes(self) -> int:
        return len(self.created) + len(self.updated) + len(self.deleted)


class Syncer:
    def __init__(self, cfg: Config, keepass: Keepass, bitwarden: Bitwarden,
                 state: State):
        self.cfg = cfg
        self.keepass = keepass
        self.bitwarden = bitwarden
        self.state = state
        self._folder_ids: dict[str, str] = {}

    # -- planning -----------------------------------------------------------
    def build_plan(self, prefer: str | None = None, deletes: str | None = None) -> Plan:
        deletes = deletes or self.cfg.deletes
        bw = self.bitwarden.entries()
        kp = self.keepass.entries()
        if not self.cfg.sync_totp:
            # TOTP is left to each vault: blanking it here keeps it out of the
            # hashes and the field diff without touching either stored value.
            bw = {key: entry.with_changes(totp="") for key, entry in bw.items()}
            kp = {key: entry.with_changes(totp="") for key, entry in kp.items()}
        plan = Plan()
        used_bw: set[str] = set()
        used_kp: set[str] = set()
        pairs: list[tuple[str, str, Link | None]] = []

        # 1. Links we already track.
        for bw_id, link in sorted(self.state.links.items()):
            has_bw, has_kp = bw_id in bw, link.kp_uuid in kp
            if has_bw and has_kp:
                pairs.append((bw_id, link.kp_uuid, link))
                used_bw.add(bw_id)
                used_kp.add(link.kp_uuid)
            elif has_bw or has_kp:
                self._plan_missing(plan, link, bw, kp, deletes)
                used_bw.add(bw_id)
                used_kp.add(link.kp_uuid)
            else:
                plan.actions.append(
                    Action("orphan", bw_id=bw_id, kp_uuid=link.kp_uuid,
                           note="link has no entry on either side")
                )

        # 2. Propose links for identical title + username pairs.
        kp_by_key: dict[tuple[str, str], list[str]] = {}
        for uuid, entry in sorted(kp.items()):
            if uuid not in used_kp:
                kp_by_key.setdefault(entry.match_key(), []).append(uuid)
        bw_by_key: dict[tuple[str, str], list[str]] = {}
        for bw_id, entry in sorted(bw.items()):
            if bw_id not in used_bw:
                bw_by_key.setdefault(entry.match_key(), []).append(bw_id)

        ambiguous_kp: set[str] = set()
        ambiguous_bw: set[str] = set()
        for key, kp_ids in sorted(kp_by_key.items()):
            bw_ids = bw_by_key.get(key, [])
            if not key[0]:
                continue  # untitled entries are never auto-linked
            if len(kp_ids) == 1 and len(bw_ids) == 1:
                pairs.append((bw_ids[0], kp_ids[0], None))
                used_bw.add(bw_ids[0])
                used_kp.add(kp_ids[0])
            elif len(kp_ids) > 1 or len(bw_ids) > 1:
                ambiguous_kp.update(kp_ids)
                ambiguous_bw.update(bw_ids)
                plan.notices.append(
                    f"ambiguous match '{kp[kp_ids[0]].title}': {len(kp_ids)} KeePass / "
                    f"{len(bw_ids)} Bitwarden candidates; not linked"
                )

        # 3. Compare each pair against the last synced hash.
        for bw_id, kp_uuid, link in pairs:
            self._plan_pair(plan, bw[bw_id], kp[kp_uuid], link, prefer)

        # 4. Entries that exist on one side only.
        for uuid, entry in sorted(kp.items()):
            if uuid in used_kp or uuid in ambiguous_kp:
                continue
            if not entry.title.strip():
                plan.notices.append(f"skipping untitled KeePass entry {uuid}")
                continue
            if self.state.is_tombstoned("keepassxc", uuid):
                plan.actions.append(Action("skip", title=entry.title, kp_uuid=uuid,
                                           note="counterpart was deleted in Bitwarden"))
                continue
            plan.actions.append(Action("create-bitwarden", title=entry.title,
                                       entry=entry, kp_uuid=uuid))

        for bw_id, entry in sorted(bw.items()):
            if bw_id in used_bw or bw_id in ambiguous_bw:
                continue
            if not entry.title.strip():
                plan.notices.append(f"skipping untitled Bitwarden item {bw_id}")
                continue
            if self.state.is_tombstoned("bitwarden", bw_id):
                plan.actions.append(Action("skip", title=entry.title, bw_id=bw_id,
                                           note="counterpart was deleted in KeePassXC"))
                continue
            plan.actions.append(Action("create-keepassxc", title=entry.title,
                                       entry=entry, bw_id=bw_id))
        return plan

    def _plan_missing(self, plan: Plan, link: Link, bw: dict[str, Entry],
                      kp: dict[str, Entry], deletes: str) -> None:
        if link.bw_id in bw:  # vanished from KeePassXC
            entry = bw[link.bw_id]
            if deletes == "propagate":
                plan.actions.append(Action("delete-bitwarden", title=entry.title,
                                           bw_id=link.bw_id, kp_uuid=link.kp_uuid,
                                           note="deleted in KeePassXC"))
            else:
                plan.actions.append(Action("missing", title=entry.title,
                                           missing_side="keepassxc", bw_id=link.bw_id,
                                           kp_uuid=link.kp_uuid,
                                           note="deleted in KeePassXC; keeping Bitwarden copy"))
        else:  # vanished from Bitwarden
            entry = kp[link.kp_uuid]
            if deletes == "propagate":
                plan.actions.append(Action("delete-keepassxc", title=entry.title,
                                           bw_id=link.bw_id, kp_uuid=link.kp_uuid,
                                           note="deleted in Bitwarden"))
            else:
                plan.actions.append(Action("missing", title=entry.title,
                                           missing_side="bitwarden", bw_id=link.bw_id,
                                           kp_uuid=link.kp_uuid,
                                           note="deleted in Bitwarden; keeping KeePass copy"))

    def _plan_pair(self, plan: Plan, bw_entry: Entry, kp_entry: Entry,
                   link: Link | None, prefer: str | None) -> None:
        bw_hash, kp_hash = bw_entry.content_hash(), kp_entry.content_hash()
        if link is None:
            if bw_hash == kp_hash:
                plan.actions.append(Action("link", title=kp_entry.title,
                                           entry=kp_entry, bw_id=bw_entry.key,
                                           kp_uuid=kp_entry.key,
                                           note="identical; recording link"))
            else:
                self._plan_conflict(plan, bw_entry, kp_entry, prefer)
            return
        changed_bw = bw_hash != link.hash
        changed_kp = kp_hash != link.hash
        if not changed_bw and not changed_kp:
            return
        if changed_bw and not changed_kp:
            plan.actions.append(Action("update-keepassxc", title=bw_entry.title,
                                       entry=bw_entry, current=kp_entry,
                                       fields=bw_entry.diff(kp_entry),
                                       bw_id=link.bw_id, kp_uuid=link.kp_uuid))
        elif changed_kp and not changed_bw:
            plan.actions.append(Action("update-bitwarden", title=kp_entry.title,
                                       entry=kp_entry, current=bw_entry,
                                       fields=kp_entry.diff(bw_entry),
                                       bw_id=link.bw_id, kp_uuid=link.kp_uuid))
        elif bw_hash == kp_hash:
            plan.actions.append(Action("link", title=kp_entry.title, entry=kp_entry,
                                       bw_id=link.bw_id, kp_uuid=link.kp_uuid,
                                       note="both sides converged; refreshing link"))
        else:
            self._plan_conflict(plan, bw_entry, kp_entry, prefer)

    def _plan_conflict(self, plan: Plan, bw_entry: Entry, kp_entry: Entry,
                       prefer: str | None) -> None:
        policy = prefer or self.cfg.conflict
        winner = ""
        if policy == "bitwarden":
            winner = "bitwarden"
        elif policy == "keepassxc":
            winner = "keepassxc"
        else:  # newest
            bw_time, kp_time = as_utc(bw_entry.updated), as_utc(kp_entry.updated)
            if bw_time and kp_time:
                if bw_time > kp_time + timedelta(seconds=1):
                    winner = "bitwarden"
                elif kp_time > bw_time + timedelta(seconds=1):
                    winner = "keepassxc"
        if not winner:
            plan.actions.append(
                Action("conflict", title=kp_entry.title, entry=kp_entry,
                       current=bw_entry, fields=bw_entry.diff(kp_entry),
                       note="both sides changed and no side is clearly newer; "
                            "re-run with --prefer bitwarden|keepassxc")
            )
            return
        if winner == "bitwarden":
            plan.actions.append(Action("update-keepassxc", title=bw_entry.title,
                                       entry=bw_entry, current=kp_entry,
                                       fields=bw_entry.diff(kp_entry),
                                       bw_id=bw_entry.key, kp_uuid=kp_entry.key))
        else:
            plan.actions.append(Action("update-bitwarden", title=kp_entry.title,
                                       entry=kp_entry, current=bw_entry,
                                       fields=kp_entry.diff(bw_entry),
                                       bw_id=bw_entry.key, kp_uuid=kp_entry.key))

    # -- applying -----------------------------------------------------------
    def apply(self, plan: Plan, deletes: str | None = None) -> Result:
        deletes = deletes or self.cfg.deletes
        result = Result()
        if not plan.actions:
            return result
        if plan.writes:
            self._backup()
        for action in plan.ordered():
            if action.kind == "conflict":
                continue
            try:
                self._apply_one(action, result, deletes)
            except (BitwardenError, KeepassError) as exc:
                result.errors.append(f"{action.kind} '{action.title}': {exc}")
        if self.keepass.dirty:
            self.keepass.save()
        self.state.save()
        return result

    def _apply_one(self, action: Action, result: Result, deletes: str) -> None:
        kind = action.kind
        if kind == "create-bitwarden":
            entry = self._require(action.entry)
            fid = self._folder_id(entry.folder)
            item = self.bitwarden.create_item(payload_from_entry(entry, fid))
            self.state.link(str(item["id"]), self._require_key(action.kp_uuid),
                            entry.content_hash())
            result.created.append(f"{entry.title} (Bitwarden)")
        elif kind == "create-keepassxc":
            entry = self._require(action.entry)
            uuid = self.keepass.create(entry)
            self.state.link(self._require_key(action.bw_id), uuid, entry.content_hash())
            result.created.append(f"{entry.title} (KeePassXC)")
        elif kind == "update-keepassxc":
            kp_uuid = self._require_key(action.kp_uuid)
            entry, outgoing = self._totp_pair(self._require(action.entry),
                                              self.keepass.totp_of(kp_uuid))
            self.keepass.update(kp_uuid, outgoing)
            self.state.link(self._require_key(action.bw_id), kp_uuid,
                            entry.content_hash())
            result.updated.append(f"{entry.title} (KeePassXC)")
        elif kind == "update-bitwarden":
            bw_id = self._require_key(action.bw_id)
            current = self.bitwarden.get_item(bw_id)
            entry, outgoing = self._totp_pair(
                self._require(action.entry), (current.get("login") or {}).get("totp")
            )
            payload = payload_from_entry(outgoing, self._folder_id(entry.folder))
            for keep in ("favorite", "organizationId", "collectionIds", "reprompt"):
                if keep in current:
                    payload[keep] = current[keep]
            self.bitwarden.update_item(bw_id, payload)
            self.state.link(bw_id, self._require_key(action.kp_uuid),
                            entry.content_hash())
            result.updated.append(f"{entry.title} (Bitwarden)")
        elif kind == "delete-keepassxc":
            self.keepass.delete(self._require_key(action.kp_uuid))
            self.state.unlink(self._require_key(action.bw_id))
            result.deleted.append(f"{action.title} (KeePassXC)")
        elif kind == "delete-bitwarden":
            self.bitwarden.delete_item(self._require_key(action.bw_id))
            self.state.unlink(self._require_key(action.bw_id))
            result.deleted.append(f"{action.title} (Bitwarden)")
        elif kind == "missing":
            if action.missing_side == "bitwarden":
                self.state.tombstone("keepassxc", self._require_key(action.kp_uuid))
                result.tombstoned.append(f"{action.title} (KeePassXC copy kept)")
            else:
                self.state.tombstone("bitwarden", self._require_key(action.bw_id))
                result.tombstoned.append(f"{action.title} (Bitwarden copy kept)")
            self.state.unlink(self._require_key(action.bw_id))
        elif kind == "link":
            entry = self._require(action.entry)
            self.state.link(self._require_key(action.bw_id),
                            self._require_key(action.kp_uuid), entry.content_hash())
        # orphan / skip need no work

    def _totp_pair(self, entry: Entry, live: object) -> tuple[Entry, Entry]:
        """Split ``entry`` into (hash basis, outgoing write) for TOTP.

        With ``totp = false`` the receiving vault keeps whatever TOTP it already
        had, while the link hash is still taken from the TOTP-free entry so the
        next run does not see a spurious change on both sides.
        """
        if self.cfg.sync_totp:
            return entry, entry
        return entry.with_changes(totp=""), entry.with_changes(totp=str(live or ""))

    @staticmethod
    def _require(value):
        if value is None:
            raise ValueError("action is missing its value")
        return value

    @staticmethod
    def _require_key(value: str | None) -> str:
        if not value:
            raise ValueError("action is missing an entry id")
        return value

    def _folder_id(self, folder: str) -> str | None:
        if not folder:
            return None
        if folder in self._folder_ids:
            return self._folder_ids[folder]
        existing = {name: fid for fid, name in self.bitwarden.folders().items()}
        fid = existing.get(folder)
        if fid is None:
            fid = self.bitwarden.create_folder(folder)
        self._folder_ids[folder] = fid
        return fid

    def _backup(self) -> Path:
        """Snapshot the encrypted .kdbx before any writes."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = Path(self.cfg.backup_dir) / stamp
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, 0o700)
        vault = target / self.cfg.database.name
        shutil.copy2(self.cfg.database, vault)
        os.chmod(vault, 0o600)
        return target
