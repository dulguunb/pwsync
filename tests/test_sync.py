from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pykeepass import PyKeePass, create_database

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwsync.bitwarden import Bitwarden
from pwsync.cli import main
from pwsync.config import Config
from pwsync.keepass import Keepass, KeepassError
from pwsync.state import State
from pwsync.sync import Syncer
from pwsync.googleauth import MigrationError, decode_uri, read_camera, secret_of
from pwsync.totp import normalize

PASSWORD = "correct horse battery staple"
NOW = datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Env:
    def __init__(self, tmp_path: Path):
        self.dir = tmp_path
        self.db = tmp_path / "vault.kdbx"
        self.store = tmp_path / "bw.json"
        self.state_file = tmp_path / "state.json"
        self.backup_dir = tmp_path / "backups"
        self.sync_totp = True
        self.exclude_groups: tuple[str, ...] = ()
        self.fake = tmp_path / "fake_bw.py"
        shutil.copy(Path(__file__).parent / "fake_bw.py", self.fake)
        self.fake.chmod(0o755)
        os.environ["FAKE_BW_STORE"] = str(self.store)
        self.store.write_text(json.dumps({"status": "unlocked", "items": [], "folders": []}))
        create_database(str(self.db), password=PASSWORD)

    @property
    def cfg(self) -> Config:
        return Config(database=self.db, bw_binary=f"{sys.executable} {self.fake}",
                      state_file=self.state_file, backup_dir=self.backup_dir,
                      sync_totp=self.sync_totp,
                      exclude_groups=self.exclude_groups)

    def kp(self) -> PyKeePass:
        return PyKeePass(str(self.db), password=PASSWORD)

    def kp_add(self, title, username="", password="", group=None, custom=None,
               otp=None, notes=None, url=None):
        kp = self.kp()
        parent = kp.root_group
        if group:
            for part in group.split("/"):
                parent = (next((g for g in parent.subgroups if g.name == part), None)
                          or kp.add_group(parent, part))
        entry = kp.add_entry(parent, title, username, password, url=url, notes=notes, otp=otp)
        for name, value in (custom or {}).items():
            entry.set_custom_property(name, value)
        kp.save()
        return str(entry.uuid)

    def kp_entries(self, include_excluded: bool = False):
        return Keepass(self.db, PASSWORD).entries(include_excluded=include_excluded)

    def kp_entry(self, title):
        return next((e for e in self.kp().entries if e.title == title), None)

    def bw(self):
        return json.loads(self.store.read_text())

    def bw_save(self, data):
        self.store.write_text(json.dumps(data, indent=2))

    def bw_add(self, title, username="", password="", folder=None, fields=None,
               totp="", notes=""):
        data = self.bw()
        folder_id = None
        if folder:
            existing = next((f for f in data["folders"] if f["name"] == folder), None)
            if existing is None:
                existing = {"id": f"folder-{len(data['folders']) + 1}", "name": folder}
                data["folders"].append(existing)
            folder_id = existing["id"]
        item = {
            "id": f"bw-{len(data['items']) + 1}", "type": 1, "name": title,
            "notes": notes, "folderId": folder_id, "revisionDate": iso(NOW),
            "login": {"username": username, "password": password, "uris": [], "totp": totp},
            "fields": [{"name": n, "value": v, "type": 0}
                       for n, v in (fields or {}).items()],
        }
        data["items"].append(item)
        self.bw_save(data)
        return item["id"]

    def bw_item(self, title):
        return next((i for i in self.bw()["items"] if i["name"] == title), None)

    def set_bw_time(self, item_id, moment):
        data = self.bw()
        for item in data["items"]:
            if item["id"] == item_id:
                item["revisionDate"] = iso(moment)
        self.bw_save(data)


def execute(env: Env, apply=True, prefer=None, deletes=None):
    cfg = env.cfg
    keepass = Keepass(cfg.database, PASSWORD, separator=cfg.folder_separator,
                      exclude=cfg.exclude_groups)
    bitwarden = Bitwarden(cfg.bw_binary)
    bitwarden.session = "fake-session"
    state = State.open(cfg.state_file)
    try:
        syncer = Syncer(cfg, keepass, bitwarden, state)
        plan = syncer.build_plan(prefer=prefer, deletes=deletes)
        result = syncer.apply(plan, deletes=deletes) if apply else None
        return plan, result
    finally:
        state.close()


def kinds(plan):
    return [action.kind for action in plan.actions]


def test_creates_missing_entries_on_both_sides(tmp_path):
    env = Env(tmp_path)
    env.kp_add("GitHub", "alice", "kp-secret")
    env.bw_add("GitLab", "bob", "bw-secret")

    plan, result = execute(env)
    assert {"create-bitwarden", "create-keepassxc"} <= set(kinds(plan))
    assert env.bw_item("GitHub")["login"]["password"] == "kp-secret"
    assert env.kp_entry("GitLab").password == "bw-secret"
    assert len(json.loads(env.state_file.read_text())["links"]) == 2

    plan2, _ = execute(env)
    assert plan2.actions == []


def test_kdbx_change_updates_bitwarden(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "old")
    execute(env)

    kp = env.kp()
    entry = next(e for e in kp.entries if e.title == "Mail")
    entry.password = "new"
    entry.mtime = NOW + timedelta(minutes=1)
    kp.save()

    plan, _ = execute(env)
    assert kinds(plan) == ["update-bitwarden"]
    assert env.bw_item("Mail")["login"]["password"] == "new"


def test_bitwarden_change_updates_kdbx(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "secret")
    execute(env)

    data = env.bw()
    data["items"][0]["login"]["password"] = "rotated"
    env.bw_save(data)

    plan, _ = execute(env)
    assert kinds(plan) == ["update-keepassxc"]
    assert env.kp_entry("Mail").password == "rotated"


def test_conflict_newest_wins(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "one")
    execute(env)

    kp = env.kp()
    entry = next(e for e in kp.entries if e.title == "Mail")
    entry.password = "kp-new"
    entry.mtime = NOW
    kp.save()
    data = env.bw()
    data["items"][0]["login"]["password"] = "bw-new"
    env.bw_save(data)
    env.set_bw_time(data["items"][0]["id"], NOW - timedelta(minutes=10))

    plan, _ = execute(env)
    assert kinds(plan) == ["update-bitwarden"]
    assert env.bw_item("Mail")["login"]["password"] == "kp-new"


def test_conflict_tie_needs_prefer(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "one")
    execute(env)

    kp = env.kp()
    entry = next(e for e in kp.entries if e.title == "Mail")
    entry.password = "kp-new"
    entry.mtime = NOW
    kp.save()
    item = env.bw_item("Mail")
    data = env.bw()
    data["items"][0]["login"]["password"] = "bw-new"
    env.bw_save(data)
    env.set_bw_time(item["id"], NOW)

    plan, _ = execute(env, apply=False)
    assert kinds(plan) == ["conflict"]
    assert "keepassxc" in plan.actions[0].note

    plan2, _ = execute(env, prefer="bitwarden")
    assert kinds(plan2) == ["update-keepassxc"]
    assert env.kp_entry("Mail").password == "bw-new"


def test_deletes_ignored_by_default(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "one")
    execute(env)

    data = env.bw()
    data["items"] = []
    env.bw_save(data)

    plan, _ = execute(env)
    assert kinds(plan) == ["missing"]
    assert env.kp_entry("Mail") is not None
    assert json.loads(env.state_file.read_text())["links"] == {}

    plan2, _ = execute(env)
    assert kinds(plan2) == ["skip"]


def test_deletes_propagate(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "one")
    execute(env)

    data = env.bw()
    data["items"] = []
    env.bw_save(data)

    plan, _ = execute(env, deletes="propagate")
    assert kinds(plan) == ["delete-keepassxc"]
    assert env.kp_entry("Mail") is None


def test_custom_fields_and_totp_roundtrip(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Bank", "alice", "pw", custom={"PIN": "1234"},
               otp="otpauth://totp/Bank?secret=ABC")
    execute(env)

    item = env.bw_item("Bank")
    assert item["login"]["totp"].startswith("otpauth://")
    assert {"name": "PIN", "value": "1234", "type": 0} in item["fields"]

    data = env.bw()
    data["items"][0]["fields"] = [{"name": "PIN", "value": "9999", "type": 0}]
    env.bw_save(data)
    execute(env)

    entry = env.kp_entry("Bank")
    assert entry.custom_properties["PIN"] == "9999"


def test_ambiguous_entries_are_neither_linked_nor_created(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "a", group="One")
    env.kp_add("Mail", "alice", "b", group="Two")
    env.bw_add("Mail", "alice", "c")

    plan, _ = execute(env, apply=False)
    assert any("ambiguous" in notice for notice in plan.notices)
    assert plan.actions == []


def test_nested_group_becomes_flat_folder(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Work", "alice", "pw", group="Personal/Email")
    execute(env)

    data = env.bw()
    folder = next(f for f in data["folders"] if f["name"] == "Personal/Email")
    assert data["items"][0]["folderId"] == folder["id"]

    entry = next(iter(env.kp_entries().values()))
    assert entry.folder == "Personal/Email"


def test_plan_writes_nothing(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "pw")
    store_before = env.store.read_text()
    db_before = env.db.read_bytes()

    plan, result = execute(env, apply=False)
    assert result is None
    assert plan.writes
    assert env.store.read_text() == store_before
    assert env.db.read_bytes() == db_before


def test_apply_backs_up_kdbx(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "pw")
    execute(env)

    backups = list(env.backup_dir.iterdir())
    assert len(backups) == 1
    files = list(backups[0].iterdir())
    assert {p.name for p in files} == {"vault.kdbx"}
    assert (backups[0] / "vault.kdbx").stat().st_mode & 0o777 == 0o600


def test_state_file_contains_no_secrets(tmp_path):
    env = Env(tmp_path)
    env.kp_add("Mail", "alice", "super-secret-password")
    execute(env)
    assert "super-secret-password" not in env.state_file.read_text()


def test_cli_status(tmp_path, capsys):
    env = Env(tmp_path)
    config = tmp_path / "pwsync.toml"
    config.write_text(
        f'[keepass]\ndatabase = "{env.db}"\n'
        f'[bitwarden]\nbinary = "{sys.executable} {env.fake}"\n'
        f'[sync]\nstate_file = "{env.state_file}"\n'
    )
    assert main(["status", "--config", str(config)]) == 0
    out = capsys.readouterr().out
    assert "links" in out
    assert "unlocked" in out


# -- TOTP ---------------------------------------------------------------

BARE = "JBSWY3DPEHPK3PXP"
OTHER_BARE = "KRSXG5CTMVRXEZLU"


def test_normalize_leaves_uris_and_junk_alone():
    assert normalize("") == ""
    uri = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme"
    assert normalize(uri) == uri
    assert normalize("abc 0189", "Acme") == "abc 0189"


def test_normalize_turns_a_seed_into_a_uri():
    out = normalize(BARE, "Acme")
    assert out.startswith("otpauth://totp/Acme?secret=JBSWY3DPEHPK3PXP")
    assert "period=30" in out and "digits=6" in out
    # lowercase, spaced and dashed seeds are accepted, as authenticator UIs show them
    assert "JBSWY3DPEHPK3PXP" in normalize("jbsw y3dp-ehpk 3pxp", "Acme")


def test_bitwarden_bare_secret_becomes_a_uri_for_keepass(tmp_path):
    env = Env(tmp_path)
    env.bw_add("Acme", "alice", "pw")
    data = env.bw()
    data["items"][0]["login"]["totp"] = BARE  # Bitwarden accepts a raw seed
    env.bw_save(data)

    execute(env)

    entry = env.kp_entry("Acme")
    assert entry.otp.startswith("otpauth://totp/")
    assert BARE in entry.otp
    # the link is stable: a second run must see no change
    plan, _ = execute(env)
    assert plan.actions == []


@pytest.mark.skipif(shutil.which("keepassxc-cli") is None,
                    reason="keepassxc-cli is not installed")
def test_keepassxc_can_generate_a_code_from_the_synced_totp(tmp_path):
    env = Env(tmp_path)
    env.bw_add("Acme", "alice", "pw")
    data = env.bw()
    data["items"][0]["login"]["totp"] = BARE
    env.bw_save(data)
    execute(env)

    proc = subprocess.run(
        ["keepassxc-cli", "show", "-q", "-t", str(env.db), "Acme"],
        input=PASSWORD + "\n", capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().isdigit()


def test_totp_disabled_lets_each_vault_keep_its_own(tmp_path):
    env = Env(tmp_path)
    env.sync_totp = False
    env.kp_add("Acme", "alice", "one", otp=f"otpauth://totp/Acme?secret={BARE}")
    execute(env)

    data = env.bw()
    data["items"][0]["login"]["totp"] = f"otpauth://totp/Acme?secret={OTHER_BARE}"
    env.bw_save(data)

    kp = env.kp()
    entry = next(e for e in kp.entries if e.title == "Acme")
    entry.password = "two"
    entry.mtime = NOW + timedelta(minutes=1)
    kp.save()

    plan, _ = execute(env)
    assert kinds(plan) == ["update-bitwarden"]
    assert env.bw_item("Acme")["login"]["totp"].endswith(OTHER_BARE)
    assert BARE in env.kp_entry("Acme").otp

    plan2, _ = execute(env)
    assert plan2.actions == []


# -- missing files ------------------------------------------------------

def _password_file(env, password=PASSWORD):
    path = env.dir / "master-pass.txt"
    path.write_text(password)
    return str(path)


def _config_for(env):
    path = env.dir / "pwsync.toml"
    exclude = ""
    if env.exclude_groups:
        listed = ", ".join(f'"{group}"' for group in env.exclude_groups)
        exclude = f"exclude = [{listed}]\n"
    path.write_text(
        f'[keepass]\ndatabase = "{env.db}"\n{exclude}'
        f'[bitwarden]\nbinary = "{sys.executable} {env.fake}"\n'
        f'[sync]\nstate_file = "{env.state_file}"\n'
        f'backup_dir = "{env.backup_dir}"\n'
    )
    return path


def test_missing_database_is_reported_not_created(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    env.db.unlink()

    code = main(["diff", "--config", str(_config_for(env)),
                 "--kdbx-password-file", _password_file(env)])

    assert code == 2

    assert not env.db.exists(), "pwsync must not invent an empty vault"
    err = capsys.readouterr().err
    assert "not found" in err
    assert "--create-database" in err


def test_missing_password_file_is_a_clean_error(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    monkeypatch.delenv("PWSYNC_KDBX_PASSWORD", raising=False)

    code = main([
        "diff", "--config", str(_config_for(env)),
        "--kdbx-password-file", str(tmp_path / "no-such-file"),
    ])

    assert code == 2
    err = capsys.readouterr().err
    assert "password file" in err
    assert "Traceback" not in err


def test_init_creates_an_empty_database(tmp_path, capsys):
    env = Env(tmp_path)
    password_file = tmp_path / "pw.txt"
    password_file.write_text("fresh-pass")
    fresh = tmp_path / "new.kdbx"
    config = tmp_path / "pwsync.toml"

    code = main([
        "init", str(config),
        "--database", str(fresh),
        "--create-database",
        "--kdbx-password-file", str(password_file),
    ])

    assert code == 0
    assert fresh.is_file()
    created = PyKeePass(str(fresh), password="fresh-pass")
    assert created.entries == []
    assert str(fresh) in config.read_text()
    assert "fresh-pass" not in config.read_text()


def test_init_refuses_to_clobber_an_existing_database(tmp_path, capsys):
    env = Env(tmp_path)
    password_file = tmp_path / "pw.txt"
    password_file.write_text(PASSWORD)
    config = tmp_path / "pwsync.toml"

    code = main([
        "init", str(config),
        "--database", str(env.db),
        "--create-database",
        "--kdbx-password-file", str(password_file),
    ])

    assert code == 2
    assert "already exists" in capsys.readouterr().err


def test_unusable_state_file_is_a_clean_error(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    config = _config_for(env)
    config.write_text(config.read_text().replace(
        f'state_file = "{env.state_file}"',
        f'state_file = "{blocker / "state.json"}"',
    ))
    code = main(["diff", "--config", str(config),
                 "--kdbx-password-file", _password_file(env)])

    assert code == 2
    err = capsys.readouterr().err
    assert "state file" in err
    assert "Traceback" not in err


def test_bitwarden_duplicates_become_duplicate_keepass_entries(tmp_path):
    """Bitwarden allows two logins with the same title and username."""
    env = Env(tmp_path)
    env.bw_add("example.com", "alice", "one")
    execute(env)  # creates the KeePass entry and the link

    # the user duplicates the item in Bitwarden
    env.bw_add("example.com", "alice", "two")

    plan, result = execute(env)
    assert kinds(plan) == ["create-keepassxc"]
    assert result.errors == []

    titles = [entry.title for entry in env.kp_entries().values()]
    assert titles.count("example.com") == 2
    assert len(json.loads(env.state_file.read_text())["links"]) == 2

    plan2, _ = execute(env)
    assert plan2.actions == []


def test_a_failed_create_does_not_abort_the_run(tmp_path, monkeypatch):
    env = Env(tmp_path)
    env.bw_add("first", "alice", "1")
    env.bw_add("second", "alice", "2")

    real_create = Keepass.create
    calls = {"n": 0}

    def flaky(self, entry):
        calls["n"] += 1
        if entry.title == "first":
            raise KeepassError("simulated failure")
        return real_create(self, entry)

    monkeypatch.setattr(Keepass, "create", flaky)

    plan, result = execute(env)

    assert len(result.errors) == 1
    assert "simulated failure" in result.errors[0]
    # the other item still made it across
    assert [e.title for e in env.kp_entries().values()] == ["second"]


def test_state_file_lock_and_directory_are_private(tmp_path):
    env = Env(tmp_path)
    state = State.open(env.state_file)
    state.save()
    state.close()

    lock = env.state_file.with_suffix(env.state_file.suffix + ".lock")
    assert env.state_file.stat().st_mode & 0o777 == 0o600
    assert lock.stat().st_mode & 0o777 == 0o600
    assert env.state_file.parent.stat().st_mode & 0o777 == 0o700


def test_warns_when_the_database_is_world_readable(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    env.kp_add("Acme", "alice", "pw")
    env.db.chmod(0o644)
    monkeypatch.setenv("BW_SESSION", "fake-session")

    main(["diff", "--config", str(_config_for(env)),
          "--kdbx-password-file", _password_file(env)])

    err = capsys.readouterr().err
    assert "readable by other users" in err
    assert "chmod 600" in err


# -- password sourcing --------------------------------------------------

def test_environment_password_is_ignored_unless_requested(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    monkeypatch.setenv("PWSYNC_KDBX_PASSWORD", PASSWORD)

    code = main(["diff", "--config", str(_config_for(env))])

    assert code == 2
    err = capsys.readouterr().err
    assert "master password" in err
    assert "kdbx-password-file" in err


def test_environment_password_works_when_explicitly_named(tmp_path, monkeypatch):
    env = Env(tmp_path)
    env.kp_add("Acme", "alice", "pw")
    monkeypatch.setenv("MY_VAULT_PW", PASSWORD)
    monkeypatch.setenv("BW_SESSION", "fake-session")

    code = main(["diff", "--config", str(_config_for(env)),
                 "--kdbx-password-env", "MY_VAULT_PW"])

    # 1 = work pending (diff's normal exit); what matters is that the vault opened
    assert code == 1


def test_named_environment_variable_must_be_set(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    monkeypatch.delenv("EMPTY_ONE", raising=False)

    code = main(["diff", "--config", str(_config_for(env)),
                 "--kdbx-password-env", "EMPTY_ONE"])

    assert code == 2
    assert "EMPTY_ONE" in capsys.readouterr().err


# -- Google Authenticator import ----------------------------------------

def _varint(n):
    out = b""
    while True:
        byte = n & 0x7F
        n >>= 7
        out += bytes([byte | (0x80 if n else 0)])
        if not n:
            return out


def _migration_uri(accounts):
    """Build a payload the way Google Authenticator writes it."""
    def key(number, wire):
        return _varint((number << 3) | wire)

    def ld(number, payload):
        return key(number, 2) + _varint(len(payload)) + payload

    def vi(number, value):
        return key(number, 0) + _varint(value)

    payload = b""
    for seed, name, issuer, algo, digits, kind, counter in accounts:
        body = (ld(1, base64.b32decode(seed)) + ld(2, name.encode())
                + ld(3, issuer.encode()) + vi(4, algo) + vi(5, digits) + vi(6, kind))
        if counter:
            body += vi(7, counter)
        payload += ld(1, body)
    payload += vi(2, 1)
    return ("otpauth-migration://offline?data="
            + base64.b64encode(payload).decode())


def test_decode_migration_payload_reads_every_field():
    uri = _migration_uri([
        ("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0),
        ("KRSXG5CTMVRXEZLU", "bob@example.com", "Bank", 2, 2, 2, 0),
        ("MFRGGZDFMZTWQ2LK", "carol@example.com", "Legacy", 1, 1, 1, 5),
    ])

    accounts, batch = decode_uri(uri)

    assert batch == 0
    assert accounts[0].secret == "JBSWY3DPEHPK3PXP"   # raw bytes, not ASCII
    assert accounts[0].algorithm == "SHA1"
    assert accounts[1].algorithm == "SHA256"
    assert accounts[1].digits == 8
    assert accounts[2].kind == "hotp"
    assert accounts[2].counter == 5
    assert accounts[1].otpauth_uri().startswith("otpauth://totp/Bank%3Abob")


def test_secret_of_ignores_the_label():
    assert secret_of("otpauth://totp/A?secret=ABC&issuer=A") == "ABC"
    assert secret_of("not a uri") == ""


def test_import_totp_writes_entries_with_otp(tmp_path, capsys):
    env = Env(tmp_path)
    uri = _migration_uri([
        ("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0),
        ("MFRGGZDFMZTWQ2LK", "carol@example.com", "Legacy", 1, 1, 1, 5),
    ])
    args = ["import-totp", "--config", str(_config_for(env)),
            "--kdbx-password-file", _password_file(env), "--data", uri]

    assert main(args) == 0

    totp = env.kp_entry("GitHub: alice@example.com")
    hotp = env.kp_entry("Legacy: carol@example.com")
    assert "JBSWY3DPEHPK3PXP" in totp.otp
    assert totp.otp.startswith("otpauth://totp/")
    assert "counter=5" in hotp.otp and hotp.otp.startswith("otpauth://hotp/")

    # importing the same export again must not duplicate anything
    assert main(args) == 0
    assert len(env.kp_entries()) == 2


def test_import_totp_rejects_a_foreign_uri(tmp_path, capsys):
    env = Env(tmp_path)
    code = main(["import-totp", "--config", str(_config_for(env)),
                 "--kdbx-password-file", _password_file(env),
                 "--data", "https://example.com/not-a-qr"])

    assert code == 2
    assert "otpauth-migration" in capsys.readouterr().err


@pytest.mark.skipif(
    not (shutil.which("zbarimg") and shutil.which("qrencode")),
    reason="needs zbarimg and qrencode",
)
def test_import_totp_reads_a_qr_screenshot(tmp_path):
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    png = tmp_path / "export.png"
    subprocess.run(["qrencode", "-o", str(png), "-t", "PNG"],
                   input=uri, text=True, check=True)

    code = main(["import-totp", "--config", str(_config_for(env)),
                 "--kdbx-password-file", _password_file(env),
                 "--image", str(png)])

    assert code == 0
    assert env.kp_entry("GitHub: alice@example.com") is not None


# -- one-way copy -------------------------------------------------------

COPY = ["copy-from-bitwarden-to-keepass"]


def _run_copy(env, command, apply=True, monkeypatch=None):
    if monkeypatch is not None:
        monkeypatch.setenv("BW_SESSION", "fake-session")
    args = command + ["--config", str(_config_for(env)),
                      "--kdbx-password-file", _password_file(env)]
    return main(args + (["--apply"] if apply else []))


def test_copy_bitwarden_to_keepass_creates_entries(tmp_path, monkeypatch):
    env = Env(tmp_path)
    env.bw_add("GitHub", "alice", "pw1", fields={"PIN": "1234"})
    bitwarden_before = env.store.read_text()

    assert _run_copy(env, COPY, monkeypatch=monkeypatch) == 0

    entry = env.kp_entry("GitHub")
    assert entry.password == "pw1"
    assert entry.username == "alice"
    assert entry.custom_properties["PIN"] == "1234"
    assert env.store.read_text() == bitwarden_before, "source must not change"


def test_copy_direction_wins_over_a_newer_keepass_change(tmp_path, monkeypatch):
    env = Env(tmp_path)
    env.bw_add("Mail", "alice", "bw-pass")
    execute(env)  # link the two sides

    kp = env.kp()
    entry = next(e for e in kp.entries if e.title == "Mail")
    entry.password = "kp-newer"
    entry.mtime = NOW + timedelta(hours=1)
    kp.save()

    assert _run_copy(env, COPY, monkeypatch=monkeypatch) == 0
    assert env.kp_entry("Mail").password == "bw-pass"


def test_copy_is_idempotent(tmp_path, monkeypatch):
    env = Env(tmp_path)
    env.bw_add("GitHub", "alice", "pw1")
    _run_copy(env, COPY, monkeypatch=monkeypatch)
    after_first = env.db.read_bytes()

    _run_copy(env, COPY, monkeypatch=monkeypatch)

    assert env.db.read_bytes() == after_first


def test_copy_dry_run_writes_nothing(tmp_path, monkeypatch):
    env = Env(tmp_path)
    env.bw_add("GitHub", "alice", "pw1")
    db_before = env.db.read_bytes()
    store_before = env.store.read_text()

    assert _run_copy(env, COPY, apply=False, monkeypatch=monkeypatch) == 0

    assert env.db.read_bytes() == db_before
    assert env.store.read_text() == store_before


def test_import_totp_scans_with_the_camera(tmp_path, monkeypatch):
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    seen = {}

    def fake_camera(device, preview=False):
        seen["device"] = device
        seen["preview"] = preview
        return uri

    monkeypatch.setattr("pwsync.cli.read_camera", fake_camera)

    code = main(["import-totp", "--config", str(_config_for(env)),
                 "--kdbx-password-file", _password_file(env), "--camera"])

    assert code == 0
    assert seen["device"] == "/dev/video0"
    assert env.kp_entry("GitHub: alice@example.com") is not None


def test_camera_device_can_be_chosen(tmp_path, monkeypatch):
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    seen = {}

    def fake_camera(device, preview=False):
        seen["device"] = device
        seen["preview"] = preview
        return uri

    monkeypatch.setattr("pwsync.cli.read_camera", fake_camera)

    main(["import-totp", "--config", str(_config_for(env)),
          "--kdbx-password-file", _password_file(env), "--camera", "/dev/video1"])

    assert seen["device"] == "/dev/video1"


def test_read_camera_explains_a_busy_device(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "VIDIOC_STREAMON: Device or resource busy"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())

    with pytest.raises(MigrationError, match="in use"):
        read_camera()


def test_read_camera_without_zbarcam(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("zbarcam")

    monkeypatch.setattr(subprocess, "run", missing)

    with pytest.raises(MigrationError, match="zbarcam is not installed"):
        read_camera()


def test_import_totp_camera_runs_zbarcam(tmp_path, monkeypatch, capsys):
    """The --camera path shells out to zbarcam for real, with a stub on PATH."""
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    stub = fake_bin / "zbarcam"
    stub.write_text(f"#!/bin/sh\ncat <<'QR'\n{uri}\nQR\n")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")

    code = main(["import-totp", "--config", str(_config_for(env)),
                 "--kdbx-password-file", _password_file(env), "--camera", "--dry-run"])

    assert code == 0
    assert "would import GitHub: alice@example.com" in capsys.readouterr().out


def test_camera_status_is_reported_while_scanning(tmp_path, monkeypatch, capsys):
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    monkeypatch.setattr("pwsync.cli.read_camera", lambda device, preview=False: uri)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    main(["import-totp", "--config", str(_config_for(env)),
          "--kdbx-password-file", _password_file(env), "--camera", "--dry-run"])

    err = capsys.readouterr().err
    assert "scanning" in err
    assert "/dev/video0" in err
    assert "read a QR code" in err
    assert "no display detected" in err


def test_preview_is_used_when_a_display_exists(tmp_path, monkeypatch):
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    seen = {}

    def fake_camera(device, preview=False):
        seen["preview"] = preview
        return uri

    monkeypatch.setattr("pwsync.cli.read_camera", fake_camera)
    monkeypatch.setenv("DISPLAY", ":0")

    main(["import-totp", "--config", str(_config_for(env)),
          "--kdbx-password-file", _password_file(env), "--camera", "--dry-run"])

    assert seen["preview"] is True


def test_no_preview_flag_disables_the_window(tmp_path, monkeypatch):
    env = Env(tmp_path)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    seen = {}

    def fake_camera(device, preview=False):
        seen["preview"] = preview
        return uri

    monkeypatch.setattr("pwsync.cli.read_camera", fake_camera)
    monkeypatch.setenv("DISPLAY", ":0")

    main(["import-totp", "--config", str(_config_for(env)),
          "--kdbx-password-file", _password_file(env), "--camera", "--no-preview", "--dry-run"])

    assert seen["preview"] is False


def test_read_camera_command_includes_the_preview_window(monkeypatch):
    calls = {}

    class Result:
        returncode = 0
        stdout = "otpauth-migration://offline?data=x"
        stderr = ""

    def fake_run(command, **kwargs):
        calls["command"] = command
        return Result()

    monkeypatch.setattr(subprocess, "run", fake_run)
    read_camera("/dev/video0", preview=True)
    assert "--nodisplay" not in calls["command"]

    read_camera("/dev/video0", preview=False)
    assert "--nodisplay" in calls["command"]


# -- excluded groups (e.g. a KeePass-only 2FA directory) ----------------

def test_excluded_group_is_left_out_of_the_sync(tmp_path):
    env = Env(tmp_path)
    env.exclude_groups = ("2FA",)
    env.kp_add("GitHub", "alice", "pw", group="2FA")
    env.kp_add("Mail", "bob", "pw2")

    plan, _ = execute(env, apply=False)

    assert [action.title for action in plan.actions] == ["Mail"]


def test_exclude_covers_subgroups(tmp_path):
    env = Env(tmp_path)
    env.exclude_groups = ("2FA",)
    env.kp_add("GitHub", "alice", "pw", group="2FA/TOTP")

    plan, _ = execute(env, apply=False)

    assert plan.actions == []


def test_reimport_into_an_excluded_group_does_not_duplicate(tmp_path):
    env = Env(tmp_path)
    env.exclude_groups = ("2FA",)
    uri = _migration_uri([("JBSWY3DPEHPK3PXP", "alice@example.com", "GitHub", 1, 1, 2, 0)])
    args = ["import-totp", "--config", str(_config_for(env)),
            "--kdbx-password-file", _password_file(env), "--group", "2FA", "--data", uri]

    assert main(args) == 0
    assert main(args) == 0

    assert len(env.kp_entries(include_excluded=True)) == 1


def test_exclude_accepts_a_comma_separated_string():
    from pwsync.config import _as_groups

    assert _as_groups("2FA, OTP") == ("2FA", "OTP")
    assert _as_groups(["2FA", "/OTP/"]) == ("2FA", "OTP")
    assert _as_groups("") == ()
