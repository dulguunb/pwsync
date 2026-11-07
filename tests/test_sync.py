from __future__ import annotations

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
from pwsync.keepass import Keepass
from pwsync.state import State
from pwsync.sync import Syncer
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
                      sync_totp=self.sync_totp)

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

    def kp_entries(self):
        return Keepass(self.db, PASSWORD).entries()

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
    keepass = Keepass(cfg.database, PASSWORD, separator=cfg.folder_separator)
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

def _config_for(env):
    path = env.dir / "pwsync.toml"
    path.write_text(
        f'[keepass]\ndatabase = "{env.db}"\n'
        f'[bitwarden]\nbinary = "{sys.executable} {env.fake}"\n'
        f'[sync]\nstate_file = "{env.state_file}"\n'
    )
    return path


def test_missing_database_is_reported_not_created(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    env.db.unlink()
    monkeypatch.setenv("PWSYNC_KDBX_PASSWORD", PASSWORD)

    assert main(["diff", "--config", str(_config_for(env))]) == 2

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
    monkeypatch.setenv("PWSYNC_KDBX_PASSWORD", PASSWORD)

    code = main(["diff", "--config", str(config)])

    assert code == 2
    err = capsys.readouterr().err
    assert "state file" in err
    assert "Traceback" not in err
