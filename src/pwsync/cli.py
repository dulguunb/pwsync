"""Command line interface for pwsync."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .bitwarden import Bitwarden, BitwardenError
from .config import DEFAULT_NAME, Config, ConfigError, example_toml, load
from .googleauth import MigrationError, decode_uri, read_qr, secret_of
from .model import Entry
from .keepass import Keepass, KeepassError
from .state import State, StateError
from .sync import Plan, Result, Syncer

COPY_COMMANDS = {
    "copy-from-bitwarden-to-keepass": "bitwarden",
    "copy-from-keepass-to-bitwarden": "keepassxc",
}

LABELS = {
    "create-bitwarden": "create -> Bitwarden",
    "create-keepassxc": "create -> KeePassXC",
    "update-bitwarden": "update -> Bitwarden",
    "update-keepassxc": "update -> KeePassXC",
    "delete-bitwarden": "delete -> Bitwarden",
    "delete-keepassxc": "delete -> KeePassXC",
    "missing": "deleted on one side",
    "conflict": "CONFLICT",
    "link": "link",
    "orphan": "orphan link",
    "skip": "keep",
}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="path to pwsync.toml")
    common.add_argument("--kdbx-password-file",
                        help="file containing the KeePass master password")
    common.add_argument("--kdbx-password-env", default=None,
                        help="read the master password from this environment variable; "
                             "opt-in, because environment variables are readable by "
                             "other processes of the same user. Without this flag the "
                             "password is prompted for and never touches the environment")

    parser = argparse.ArgumentParser(
        prog="pwsync",
        description="Two-way password sync between KeePassXC and Bitwarden.",
    )
    parser.add_argument("--version", action="version", version=f"pwsync {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", parents=[common],
                          help="write a configuration template")
    init.add_argument("path", nargs="?", default=DEFAULT_NAME)
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.add_argument("--database", help="KeePass database path to record in the config")
    init.add_argument("--create-database", action="store_true",
                      help="create an empty .kdbx at --database if it is missing")

    sub.add_parser("status", parents=[common], help="show vault and link status")

    for name, help_text in (("diff", "show what a sync would change"),
                            ("apply", "apply the pending changes")):
        cmd = sub.add_parser(name, parents=[common], help=help_text)
        cmd.add_argument("--prefer", choices=("newest", "bitwarden", "keepassxc"),
                         help="conflict policy for this run")
        cmd.add_argument("--deletes", choices=("ignore", "propagate"),
                         help="deletion policy for this run")
        if name == "apply":
            cmd.add_argument("--dry-run", action="store_true",
                             help="print the plan without writing anything")

    link = sub.add_parser("link", parents=[common], help="manually link two entries")
    link.add_argument("--bw-id", required=True)
    link.add_argument("--keepass-uuid", required=True)
    link.add_argument("--prefer", choices=("bitwarden", "keepassxc"), default="keepassxc",
                      help="side whose current content is treated as correct")

    unlink = sub.add_parser("unlink", parents=[common], help="drop a recorded link")
    unlink.add_argument("--bw-id", required=True)

    for name, side, target in (
        ("copy-from-bitwarden-to-keepass", "Bitwarden", "KeePassXC"),
        ("copy-from-keepass-to-bitwarden", "KeePassXC", "Bitwarden"),
    ):
        cmd = sub.add_parser(
            name, parents=[common],
            help=f"one-way copy of every {side} entry into {target} "
                 f"({side} is never modified)",
        )
        cmd.add_argument("--apply", action="store_true",
                         help="write the copy (default: preview only)")

    imp = sub.add_parser(
        "import-totp", parents=[common],
        help="import TOTP accounts from a Google Authenticator export QR",
    )
    imp.add_argument("--data", action="append", default=[], metavar="URI",
                     help="an otpauth-migration:// string from the export QR")
    imp.add_argument("--image", action="append", default=[], metavar="FILE",
                     help="screenshot of that QR (decoded with zbarimg)")
    imp.add_argument("--group", default="",
                     help="KeePass group to import into (default: the sync root)")
    imp.add_argument("--dry-run", action="store_true", help="list without writing")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except (ConfigError, KeepassError, BitwardenError, StateError) as exc:
        print(f"pwsync: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # Disk full, permission denied, a vanished mount: say so plainly.
        where = exc.filename or ""
        detail = exc.strerror or str(exc)
        print(f"pwsync: {detail}{f': {where}' if where else ''}", file=sys.stderr)
        return 2


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "init":
        return _init(args)

    cfg = load(args.config)
    if args.command == "status":
        return _status(cfg)
    if args.command == "unlink":
        return _unlink(cfg, args)
    if args.command == "import-totp":
        return _import_totp(cfg, args)
    if args.command in COPY_COMMANDS:
        return _copy(cfg, args, COPY_COMMANDS[args.command])
    if args.command == "link":
        return _link(cfg, args)

    state = State.open(cfg.state_file)
    try:
        with _vaults(cfg, args) as (keepass, bitwarden):
            syncer = Syncer(cfg, keepass, bitwarden, state)
            plan = syncer.build_plan(prefer=getattr(args, "prefer", None),
                                     deletes=getattr(args, "deletes", None))
            applying = args.command == "apply" and not getattr(args, "dry_run", False)
            _print_plan(plan, hint=not applying)
            if args.command == "diff" or getattr(args, "dry_run", False):
                return 1 if plan.conflicts or plan.writes else 0
            result = syncer.apply(plan, deletes=getattr(args, "deletes", None))
            _print_result(result)
            return 1 if result.errors else 0
    finally:
        state.close()


class _vaults:
    """Open both vaults, unlocking Bitwarden on demand, and never leak secrets."""

    def __init__(self, cfg: Config, args: argparse.Namespace):
        self.cfg = cfg
        self.args = args

    def __enter__(self):
        password = _kdbx_password(self.args)
        keepass = Keepass(
            self.cfg.database,
            password,
            root_group=self.cfg.root_group,
            keyfile=self.cfg.keyfile,
            separator=self.cfg.folder_separator,
        )
        if keepass.loose_permissions():
            print(
                f"warning: {keepass.path} is readable by other users; "
                f"consider `chmod 600 {keepass.path}`",
                file=sys.stderr,
            )
        bitwarden = Bitwarden(self.cfg.bw_binary)
        try:
            bitwarden.ensure_session()
        except BitwardenError as exc:
            message = str(exc).lower()
            if sys.stdin.isatty() and ("locked" in message or "bw_session" in message):
                bitwarden.password = getpass.getpass("Bitwarden master password: ")
                bitwarden.ensure_session()
            else:
                raise
        return keepass, bitwarden

    def __exit__(self, *exc_info) -> None:
        return None


def _init(args: argparse.Namespace) -> int:
    config_path = Path(args.path).expanduser()
    if config_path.exists() and not args.force:
        raise ConfigError(f"{config_path} already exists; pass --force to overwrite")

    database = str(Path(args.database).expanduser()) if args.database else None
    if args.create_database:
        if not database:
            raise ConfigError("--create-database needs --database PATH")
        target = Path(database)
        if target.exists():
            raise ConfigError(f"{target} already exists")
        Keepass.create_database(target, _kdbx_password(args))
        print(f"created {target}")

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(example_toml(database), encoding="utf-8")
    print(f"wrote {config_path}")
    return 0


def _kdbx_password(args: argparse.Namespace) -> str:
    """The KeePass master password.

    Order: an explicit file, then an explicitly named environment variable, then
    an interactive prompt. The environment is never consulted by default --
    ``/proc/<pid>/environ`` is readable by other processes of the same user, so
    the password only goes there when the user asks for it (cron, systemd).
    """
    path = getattr(args, "kdbx_password_file", None)
    if path:
        source = Path(path).expanduser()
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(
                f"cannot read the KeePass password file {source}: "
                f"{exc.strerror or exc}"
            ) from exc
        # Only drop the trailing newline; passwords may legitimately contain
        # leading/trailing whitespace.
        text = text.splitlines()[0] if text.splitlines() else ""
        if not text:
            raise ConfigError(f"{path} is empty")
        return text
    env_name = getattr(args, "kdbx_password_env", None)
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value
        raise ConfigError(
            f"--kdbx-password-env {env_name} was given but that variable is empty"
        )
    if sys.stdin.isatty():
        return getpass.getpass("KeePass master password: ")
    raise ConfigError(
        "no way to read the KeePass master password: run pwsync in a terminal to "
        "be prompted, or pass --kdbx-password-file PATH (or --kdbx-password-env "
        "NAME for unattended runs)"
    )


def _print_plan(plan: Plan, hint: bool = True) -> None:
    for notice in plan.notices:
        print(f"note: {notice}")
    visible = [a for a in plan.ordered() if a.kind != "skip"]
    if not visible:
        if not plan.notices:
            print("Everything is in sync.")
    for action in visible:
        label = LABELS.get(action.kind, action.kind)
        line = f"  {label:<22} {action.title}"
        detail = action.describe_fields()
        if detail:
            line += f"  ({detail})"
        if action.note:
            line += f"  [{action.note}]"
        print(line)
    skipped = [a for a in plan.ordered() if a.kind == "skip"]
    if skipped:
        print(f"  ({len(skipped)} tombstoned entr{'y' if len(skipped) == 1 else 'ies'} left alone)")
    if plan.writes and hint:
        print(f"\n{len(plan.writes)} change(s) pending; run `pwsync apply` to write them.")


def _print_result(result: Result) -> None:
    print(
        f"done: {len(result.created)} created, {len(result.updated)} updated, "
        f"{len(result.deleted)} deleted, {len(result.tombstoned)} tombstoned"
    )
    for line in result.created + result.updated + result.deleted:
        print(f"  + {line}")
    for error in result.errors:
        print(f"  ! {error}", file=sys.stderr)


def _status(cfg: Config) -> int:
    print(f"config      {cfg.config_path}")
    print(f"database    {cfg.database} ({'ok' if cfg.database.is_file() else 'MISSING'})")
    try:
        state = Bitwarden(cfg.bw_binary).status()
        line = str(state.get("status"))
        if state.get("userEmail"):
            line += f"  {state['userEmail']}"
        print(f"bitwarden   {line}")
    except BitwardenError as exc:
        print(f"bitwarden   error: {exc}")
    record = State.open(cfg.state_file)
    try:
        tombstones = sum(len(side) for side in record.tombstones.values())
        print(f"links       {len(record.links)}")
        print(f"tombstones  {tombstones}")
    finally:
        record.close()
    return 0


def _copy(cfg: Config, args: argparse.Namespace, source: str) -> int:
    state = State.open(cfg.state_file)
    try:
        with _vaults(cfg, args) as (keepass, bitwarden):
            syncer = Syncer(cfg, keepass, bitwarden, state)
            plan = syncer.build_copy_plan(source)
            _print_plan(plan, hint=False)
            if not args.apply:
                if plan.writes:
                    print(f"\ndry run: {len(plan.writes)} change(s) not written. "
                          f"Re-run with --apply to copy.")
                return 0
            if not plan.writes:
                return 0
            result = syncer.apply(plan)
            _print_result(result)
            return 1 if result.errors else 0
    finally:
        state.close()


def _import_totp(cfg: Config, args: argparse.Namespace) -> int:
    uris = list(args.data)
    for image in args.image:
        uris.append(read_qr(image))
    if not uris:
        raise ConfigError("nothing to import: pass --data URI or --image FILE")

    accounts = []
    for uri in uris:
        try:
            found, _batch = decode_uri(uri)
        except MigrationError as exc:
            raise ConfigError(str(exc)) from exc
        accounts.extend(found)

    keepass = Keepass(
        cfg.database,
        _kdbx_password(args),
        root_group=cfg.root_group,
        keyfile=cfg.keyfile,
        separator=cfg.folder_separator,
    )
    # Compare on the secret itself: the same seed may already be stored with a
    # different label or parameter order.
    known = {secret_of(entry.totp) for entry in keepass.entries().values() if entry.totp}

    imported = skipped = 0
    for account in accounts:
        if account.secret in known:
            skipped += 1
            continue
        known.add(account.secret)
        imported += 1
        if args.dry_run:
            print(f"  would import {account.title} ({account.kind.upper()})")
            continue
        keepass.create(Entry(
            title=account.title,
            username=account.name,
            password="",
            totp=account.otpauth_uri(),
            folder=args.group,
        ))
        print(f"  imported {account.title} ({account.kind.upper()})")

    if not args.dry_run and keepass.dirty:
        keepass.save()
    verb = "would import" if args.dry_run else "imported"
    print(f"{imported} {verb}, {skipped} already present")
    return 0


def _link(cfg: Config, args: argparse.Namespace) -> int:
    state = State.open(cfg.state_file)
    try:
        with _vaults(cfg, args) as (keepass, bitwarden):
            kp_entries = keepass.entries()
            bw_entries = bitwarden.entries()
            if args.keepass_uuid not in kp_entries:
                raise ConfigError(f"no KeePass entry with UUID {args.keepass_uuid}")
            if args.bw_id not in bw_entries:
                raise ConfigError(f"no Bitwarden login item with id {args.bw_id}")
            kp_entry = kp_entries[args.keepass_uuid]
            bw_entry = bw_entries[args.bw_id]
            winning = kp_entry if args.prefer == "keepassxc" else bw_entry
            state.link(args.bw_id, args.keepass_uuid, winning.content_hash())
            state.save()
            print(f"linked '{kp_entry.title}' <-> '{bw_entry.title}' ({args.prefer} wins)")
            return 0
    finally:
        state.close()


def _unlink(cfg: Config, args: argparse.Namespace) -> int:
    state = State.open(cfg.state_file)
    try:
        if args.bw_id not in state.links:
            raise ConfigError(f"no recorded link for Bitwarden item {args.bw_id}")
        state.unlink(args.bw_id)
        state.save()
        print(f"unlinked {args.bw_id}")
        return 0
    finally:
        state.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
