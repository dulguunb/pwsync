"""Bitwarden access through the official ``bw`` CLI.

Every operation shells out to ``bw``; the session key and master password are
passed through the environment, never through argv, and are redacted from any
error text we surface.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import subprocess
from datetime import datetime

from .model import Entry, as_utc

LOGIN_ITEM_TYPE = 1


class BitwardenError(RuntimeError):
    """A failed or impossible Bitwarden CLI call."""


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _b64(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def item_to_entry(item: dict, folder_names: dict[str, str]) -> Entry:
    login = item.get("login") or {}
    url = ""
    for uri in login.get("uris") or []:
        if isinstance(uri, dict) and uri.get("uri"):
            url = uri["uri"]
            break
    fields: list[tuple[str, str]] = []
    for field in item.get("fields") or []:
        if not isinstance(field, dict) or not field.get("name"):
            continue
        if int(field.get("type", 0) or 0) not in (0, 1):  # skip boolean/linked
            continue
        fields.append((field["name"], field.get("value") or ""))
    return Entry(
        title=item.get("name") or "",
        username=login.get("username") or "",
        password=login.get("password") or "",
        url=url,
        notes=item.get("notes") or "",
        totp=login.get("totp") or "",
        folder=folder_names.get(item.get("folderId") or "", ""),
        custom=tuple(fields),
        updated=_parse_time(item.get("revisionDate")),
        key=item.get("id") or "",
    )


def payload_from_entry(entry: Entry, folder_id: str | None) -> dict:
    login: dict[str, object] = {
        "username": entry.username,
        "password": entry.password,
        "uris": [{"match": None, "uri": entry.url}] if entry.url else [],
    }
    if entry.totp:
        login["totp"] = entry.totp
    return {
        "type": LOGIN_ITEM_TYPE,
        "name": entry.title,
        "notes": entry.notes,
        "favorite": False,
        "folderId": folder_id,
        "login": login,
        "fields": [
            {"name": name, "value": value, "type": 0} for name, value in entry.custom
        ],
        "reprompt": 0,
    }


class Bitwarden:
    def __init__(self, binary: str = "bw", session: str | None = None, password: str | None = None):
        self.binary = binary
        self.session = session or os.environ.get("BW_SESSION") or None
        self.password = password or os.environ.get("BW_PASSWORD") or None
        self._items: list[dict] | None = None
        self._folders: dict[str, str] | None = None

    # -- process plumbing ---------------------------------------------------
    def _run(self, *args: str) -> str:
        command = shlex.split(self.binary) + list(args)
        env = dict(os.environ)
        if self.session:
            env["BW_SESSION"] = self.session
        if self.password:
            env["BW_PASSWORD"] = self.password
        try:
            proc = subprocess.run(command, capture_output=True, text=True, env=env)
        except FileNotFoundError as exc:
            raise BitwardenError(f"Bitwarden CLI not found: {command[0]}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            if self.password:
                detail = detail.replace(self.password, "***")
            if self.session:
                detail = detail.replace(self.session, "***")
            # bw may echo the base64 payload (which contains the password) in an
            # error. Mask any long base64-looking token to keep credentials out of
            # the terminal.
            detail = re.sub(r"[A-Za-z0-9+/]{80,}={0,2}", "***", detail)
            raise BitwardenError(
                f"`bw {args[0] if args else ''}` failed ({proc.returncode}): {detail[:500]}"
            )
        return proc.stdout

    # -- session ------------------------------------------------------------
    def status(self) -> dict:
        out = self._run("status")
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise BitwardenError(f"unexpected `bw status` output: {out[:200]}") from exc

    def ensure_session(self) -> str:
        state = str(self.status().get("status"))
        if state == "unauthenticated":
            raise BitwardenError("Bitwarden CLI is not logged in; run `bw login` first")
        if state == "locked":
            if not self.password:
                raise BitwardenError(
                    "Bitwarden vault is locked; export BW_PASSWORD or run `bw unlock`"
                )
            session = self._run(
                "unlock", "--raw", "--passwordenv", "BW_PASSWORD"
            ).strip()
            if not session:
                raise BitwardenError("`bw unlock --raw` returned no session key")
            self.session = session
        elif not self.session:
            raise BitwardenError("Bitwarden reports unlocked but BW_SESSION is not set")
        assert self.session is not None
        return self.session

    def sync(self) -> None:
        self.ensure_session()
        self._run("sync", "--session", self.session)
        self._items = None
        self._folders = None

    # -- reads --------------------------------------------------------------
    def _json(self, *args: str) -> object:
        self.ensure_session()
        out = self._run(*args, "--session", self.session)
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise BitwardenError(f"unexpected JSON from `bw {args[0]}`") from exc

    def folders(self) -> dict[str, str]:
        if self._folders is None:
            data = self._json("list", "folders")
            self._folders = {
                str(folder["id"]): str(folder.get("name", "")) for folder in data
            }
        return self._folders

    def folder_ids(self) -> dict[str, str]:
        return {name: fid for fid, name in self.folders().items()}

    def items(self) -> list[dict]:
        if self._items is None:
            data = self._json("list", "items")
            self._items = [
                item
                for item in data
                if int(item.get("type", 0) or 0) == LOGIN_ITEM_TYPE
                and not item.get("deletedDate")
            ]
        return self._items

    def entries(self) -> dict[str, Entry]:
        names = self.folders()
        return {str(item["id"]): item_to_entry(item, names) for item in self.items()}

    def get_item(self, item_id: str) -> dict:
        return self._json("get", "item", item_id)

    # -- writes -------------------------------------------------------------
    def create_item(self, payload: dict) -> dict:
        self.ensure_session()
        out = self._run("create", "item", _b64(payload), "--session", self.session)
        self._items = None
        return json.loads(out)

    def update_item(self, item_id: str, payload: dict) -> dict:
        self.ensure_session()
        body = dict(payload, id=item_id)
        out = self._run("edit", "item", item_id, _b64(body), "--session", self.session)
        self._items = None
        return json.loads(out)

    def delete_item(self, item_id: str) -> None:
        self.ensure_session()
        self._run("delete", "item", item_id, "--session", self.session)
        self._items = None

    def create_folder(self, name: str) -> str:
        self.ensure_session()
        out = self._run("create", "folder", _b64({"name": name}), "--session", self.session)
        self._folders = None
        return str(json.loads(out)["id"])
