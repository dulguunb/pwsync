#!/usr/bin/env python3
"""Minimal `bw` CLI stand-in backed by a JSON file, for the test suite."""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def store() -> Path:
    return Path(os.environ["FAKE_BW_STORE"])


def load() -> dict:
    path = store()
    if not path.exists():
        return {"status": "unlocked", "items": [], "folders": []}
    return json.loads(path.read_text())


def save(data: dict) -> None:
    store().write_text(json.dumps(data, indent=2))


def positional(argv: list[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg == "--session":
            skip = True
            continue
        if arg.startswith("--session="):
            continue
        out.append(arg)
    return out


def decode(arg: str) -> dict:
    return json.loads(base64.b64decode(arg).decode("utf-8"))


def main(argv: list[str]) -> int:
    args = positional(argv[1:])
    data = load()
    if args[:1] == ["status"]:
        print(json.dumps({"status": data.get("status", "unlocked"),
                          "userEmail": "test@example.com", "serverUrl": None}))
        return 0
    if args[:1] == ["unlock"]:
        print("fake-session-key")
        return 0
    if args[:1] == ["sync"]:
        print("Syncing complete.")
        return 0
    if args[:2] == ["list", "items"]:
        print(json.dumps(data["items"]))
        return 0
    if args[:2] == ["list", "folders"]:
        print(json.dumps(data["folders"]))
        return 0
    if args[:2] == ["get", "item"]:
        item = next((i for i in data["items"] if i["id"] == args[2]), None)
        if item is None:
            print("Not found.", file=sys.stderr)
            return 1
        print(json.dumps(item))
        return 0
    if args[:2] == ["create", "item"]:
        payload = decode(args[2])
        item = {"id": str(uuid.uuid4()), "type": 1, "deletedDate": None,
                "revisionDate": now(), **payload}
        data["items"].append(item)
        save(data)
        print(json.dumps(item))
        return 0
    if args[:2] == ["edit", "item"]:
        item_id, payload = args[2], decode(args[3])
        item = next((i for i in data["items"] if i["id"] == item_id), None)
        if item is None:
            print("Not found.", file=sys.stderr)
            return 1
        item.update(payload)
        item["id"] = item_id
        item["revisionDate"] = now()
        save(data)
        print(json.dumps(item))
        return 0
    if args[:2] == ["delete", "item"]:
        data["items"] = [i for i in data["items"] if i["id"] != args[2]]
        save(data)
        print("Deleted.")
        return 0
    if args[:2] == ["create", "folder"]:
        payload = decode(args[2])
        folder = {"id": str(uuid.uuid4()), "name": payload["name"]}
        data["folders"].append(folder)
        save(data)
        print(json.dumps(folder))
        return 0
    print(f"fake bw: unsupported command: {args}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
