"""Configuration loading for pwsync."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_ENV = "PWSYNC_CONFIG"
DEFAULT_NAME = "pwsync.toml"
DEFAULT_STATE_FILE = Path.home() / ".local/state/pwsync/state.json"
DEFAULT_BACKUP_DIR = Path.home() / ".local/state/pwsync/backups"
CONFLICT_POLICIES = ("newest", "bitwarden", "keepassxc")
DELETE_POLICIES = ("ignore", "propagate")


class ConfigError(Exception):
    """A missing or invalid configuration."""


def expand_path(value: str, base: Path | None = None) -> Path:
    text = os.path.expandvars(str(value))
    path = Path(os.path.expanduser(text))
    if not path.is_absolute() and base is not None:
        path = (base / path).resolve()
    return path


@dataclass
class Config:
    database: Path
    root_group: str = ""
    keyfile: Path | None = None
    bw_binary: str = "bw"
    folder_separator: str = "/"
    conflict: str = "newest"
    deletes: str = "ignore"
    sync_custom_fields: bool = True
    sync_totp: bool = True
    state_file: Path = field(default_factory=lambda: DEFAULT_STATE_FILE)
    backup_dir: Path = field(default_factory=lambda: DEFAULT_BACKUP_DIR)
    config_path: Path | None = None

    def validate(self) -> None:
        if self.conflict not in CONFLICT_POLICIES:
            raise ConfigError(
                f"sync.conflict must be one of {', '.join(CONFLICT_POLICIES)}"
            )
        if self.deletes not in DELETE_POLICIES:
            raise ConfigError(
                f"sync.deletes must be one of {', '.join(DELETE_POLICIES)}"
            )
        if not self.folder_separator:
            raise ConfigError("bitwarden.folder_separator must not be empty")


def find_config(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return path
    env = os.environ.get(CONFIG_ENV)
    if env:
        path = Path(env).expanduser()
        if not path.is_file():
            raise ConfigError(f"{CONFIG_ENV} points at a missing file: {path}")
        return path
    for candidate in (
        Path.cwd() / DEFAULT_NAME,
        Path.home() / ".config" / "pwsync" / DEFAULT_NAME,
    ):
        if candidate.is_file():
            return candidate
    raise ConfigError(
        f"no {DEFAULT_NAME} found in the current directory or ~/.config/pwsync; "
        "run `pwsync init` to create one"
    )


def load(explicit: str | None = None) -> Config:
    path = find_config(explicit)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    kp = raw.get("keepass", {})
    bw = raw.get("bitwarden", {})
    sync = raw.get("sync", {})
    if not isinstance(kp, dict) or not isinstance(bw, dict) or not isinstance(sync, dict):
        raise ConfigError(f"{path}: keepass, bitwarden and sync must be tables")
    if "database" not in kp:
        raise ConfigError(f"{path}: [keepass] database is required")

    base = path.parent
    cfg = Config(
        database=expand_path(kp["database"], base),
        root_group=str(kp.get("root_group", "") or ""),
        keyfile=expand_path(kp["keyfile"], base) if kp.get("keyfile") else None,
        bw_binary=str(bw.get("binary", "bw")),
        folder_separator=str(bw.get("folder_separator", "/")),
        conflict=str(sync.get("conflict", "newest")),
        deletes=str(sync.get("deletes", "ignore")),
        sync_custom_fields=bool(sync.get("custom_fields", True)),
        sync_totp=bool(sync.get("totp", True)),
        state_file=expand_path(str(sync.get("state_file", DEFAULT_STATE_FILE)), base),
        backup_dir=expand_path(str(sync.get("backup_dir", DEFAULT_BACKUP_DIR)), base),
        config_path=path,
    )
    cfg.validate()
    return cfg


def example_toml() -> str:
    return """\
# pwsync configuration — see README.md for details.
# Secrets never belong in this file.

[keepass]
# Path to the .kdbx database (relative paths resolve against this file's directory).
database = "~/Passwords.kdbx"
# Optional: sync only this group subtree (created on first apply when missing).
root_group = ""
# keyfile = "~/.config/keepassxc/keyfile"

[bitwarden]
# CLI used for every Bitwarden call. BW_SESSION / BW_PASSWORD come from the
# environment, or you will be prompted for the master password.
binary = "bw"
# KeePass groups are nested; Bitwarden folders are flat, so a path like
# "Personal/Email" becomes one folder with that literal name.
folder_separator = "/"

[sync]
# newest | bitwarden | keepassxc — used when both sides changed.
conflict = "newest"
# ignore | propagate — whether deletions travel across the sync.
deletes = "ignore"
custom_fields = true
totp = true
# state_file = "~/.local/state/pwsync/state.json"
# backup_dir = "~/.local/state/pwsync/backups"
"""
