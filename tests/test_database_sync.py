from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pykeepass import PyKeePass, create_database

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwsync.cli import main
from pwsync.keepass import Keepass, KeepassError
from pwsync.database_sync import apply_database_sync, plan_database_sync

PASSWORD_A = "test vault A passphrase"
PASSWORD_B = "test vault B passphrase"


class VaultPair:
    def __init__(self, tmp_path: Path):
        self.dir = tmp_path
        self.path_a = tmp_path / "a.kdbx"
        self.path_b = tmp_path / "b.kdbx"
        self.backups = tmp_path / "backups"
        create_database(str(self.path_a), password=PASSWORD_A)
        create_database(str(self.path_b), password=PASSWORD_B)

    def add(self, side: str, title: str, username: str, password: str,
            group: str = "", notes: str = "", url: str = "", otp: str = "",
            custom: dict[str, str] | None = None) -> None:
        path, master = ((self.path_a, PASSWORD_A) if side == "a"
                        else (self.path_b, PASSWORD_B))
        kp = PyKeePass(str(path), password=master)
        parent = kp.root_group
        for part in filter(None, group.split("/")):
            parent = next((g for g in parent.subgroups if g.name == part), None) \
                or kp.add_group(parent, part)
        entry = kp.add_entry(parent, title, username, password, notes=notes,
                             url=url, otp=otp, force_creation=True)
        for name, value in (custom or {}).items():
            entry.set_custom_property(name, value)
        kp.save()

    def entries(self, side: str):
        path, master = ((self.path_a, PASSWORD_A) if side == "a"
                        else (self.path_b, PASSWORD_B))
        return Keepass(path, master).entries()

    def values(self, side: str, title: str):
        return sorted((entry.password, entry.notes, entry.folder)
                      for entry in self.entries(side).values() if entry.title == title)

    def pair(self):
        return (Keepass(self.path_a, PASSWORD_A), Keepass(self.path_b, PASSWORD_B))


def test_sync_copies_missing_entries_both_directions(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "A only", "alice", "a-pass", group="Work/Apps")
    vaults.add("b", "B only", "bob", "b-pass", notes="from B")

    left, right = vaults.pair()
    plan = plan_database_sync(left, right)
    result = apply_database_sync(left, right, plan, vaults.backups)

    assert result.added_to_a == 1
    assert result.added_to_b == 1
    assert vaults.values("a", "B only") == [("b-pass", "from B", "")]
    assert vaults.values("b", "A only") == [("a-pass", "", "Work/Apps")]


def test_same_title_username_different_passwords_keep_both_versions(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "mail", "alice", "old-pass", notes="A's note")
    vaults.add("b", "mail", "alice", "new-pass", notes="B's note")

    left, right = vaults.pair()
    plan = plan_database_sync(left, right)
    result = apply_database_sync(left, right, plan, vaults.backups)

    expected = [("new-pass", "B's note", ""), ("old-pass", "A's note", "")]
    assert result.added_to_a == result.added_to_b == 1
    assert plan.conflicts == 1
    assert vaults.values("a", "mail") == expected
    assert vaults.values("b", "mail") == expected


def test_matching_content_is_not_duplicated(tmp_path):
    vaults = VaultPair(tmp_path)
    for side in ("a", "b"):
        vaults.add(side, "shared", "alice", "same-pass", group="Home")

    left, right = vaults.pair()
    plan = plan_database_sync(left, right)

    assert plan.add_to_a == []
    assert plan.add_to_b == []
    result = apply_database_sync(left, right, plan, vaults.backups)
    assert result.added_to_a == result.added_to_b == 0
    assert not vaults.backups.exists()


def test_duplicate_multiplicity_is_equalized_without_repeating(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "shared", "alice", "same-pass")
    vaults.add("a", "shared", "alice", "same-pass")
    vaults.add("b", "shared", "alice", "same-pass")

    left, right = vaults.pair()
    result = apply_database_sync(left, right, plan_database_sync(left, right),
                                 vaults.backups)

    assert result.added_to_a == 0
    assert result.added_to_b == 1
    assert len(vaults.entries("a")) == len(vaults.entries("b")) == 2

    left, right = vaults.pair()
    plan = plan_database_sync(left, right)
    assert plan.add_to_a == [] and plan.add_to_b == []


def test_preview_never_changes_database_bytes_or_creates_backups(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "A only", "alice", "secret")
    before_a, before_b = vaults.path_a.read_bytes(), vaults.path_b.read_bytes()

    left, right = vaults.pair()
    plan = plan_database_sync(left, right)

    assert plan.add_to_a or plan.add_to_b
    assert vaults.path_a.read_bytes() == before_a
    assert vaults.path_b.read_bytes() == before_b
    assert not vaults.backups.exists()


def test_second_run_is_idempotent_and_does_not_rewrite_files(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "A only", "alice", "secret")
    left, right = vaults.pair()
    apply_database_sync(left, right, plan_database_sync(left, right), vaults.backups)
    before_a, before_b = vaults.path_a.read_bytes(), vaults.path_b.read_bytes()
    backup_count = len(list(vaults.backups.iterdir()))

    left, right = vaults.pair()
    result = apply_database_sync(left, right, plan_database_sync(left, right),
                                 vaults.backups)

    assert result.added_to_a == result.added_to_b == 0
    assert vaults.path_a.read_bytes() == before_a
    assert vaults.path_b.read_bytes() == before_b
    assert len(list(vaults.backups.iterdir())) == backup_count


def test_configured_root_group_is_respected(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "inside", "alice", "secret", group="Sync")
    vaults.add("a", "outside", "bob", "secret")
    left = Keepass(vaults.path_a, PASSWORD_A, root_group="Sync")
    right = Keepass(vaults.path_b, PASSWORD_B, root_group="Sync")

    plan = plan_database_sync(left, right)
    result = apply_database_sync(left, right, plan, vaults.backups)

    assert result.added_to_b == 1
    assert result.added_to_a == 0
    assert [entry.title for entry in Keepass(vaults.path_b, PASSWORD_B,
                                             root_group="Sync").entries().values()] == ["inside"]


def test_cli_preview_and_apply_prompt_for_both_passwords(tmp_path, monkeypatch, capsys):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "A only", "alice", "secret")
    monkeypatch.setattr("pwsync.cli.sys.stdin.isatty", lambda: True)
    answers = iter((PASSWORD_A, PASSWORD_B))
    monkeypatch.setattr("pwsync.cli.getpass.getpass", lambda _prompt: next(answers))
    args = ["sync-keepass-databases", str(vaults.path_a), str(vaults.path_b),
            "--backup-dir", str(vaults.backups)]

    assert main(args) == 0
    preview = capsys.readouterr().out
    assert "preview" in preview.lower()
    assert "nothing written" in preview.lower()
    assert len(Keepass(vaults.path_b, PASSWORD_B).entries()) == 0

    answers = iter((PASSWORD_A, PASSWORD_B))
    monkeypatch.setattr("pwsync.cli.getpass.getpass", lambda _prompt: next(answers))
    assert main(args + ["--apply"]) == 0
    assert len(Keepass(vaults.path_b, PASSWORD_B).entries()) == 1


def test_cli_refuses_same_database_twice_without_prompting(tmp_path, monkeypatch):
    vaults = VaultPair(tmp_path)
    monkeypatch.setattr("pwsync.cli.sys.stdin.isatty", lambda: True)

    def unexpected_prompt(_prompt):
        pytest.fail("must reject identical paths before asking for passwords")

    monkeypatch.setattr("pwsync.cli.getpass.getpass", unexpected_prompt)

    assert main(["sync-keepass-databases", str(vaults.path_a), str(vaults.path_a)]) == 2


def test_noninteractive_cli_refuses_before_reading_any_password(tmp_path, monkeypatch, capsys):
    vaults = VaultPair(tmp_path)
    monkeypatch.setattr("pwsync.cli.sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("pwsync.cli.getpass.getpass",
                        lambda _prompt: pytest.fail("password prompt must not run"))

    assert main(["sync-keepass-databases", str(vaults.path_a), str(vaults.path_b)]) == 2
    assert "interactive terminal" in capsys.readouterr().err


def test_plan_detects_file_changed_since_it_was_opened(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "A only", "alice", "secret")
    left, right = vaults.pair()
    plan = plan_database_sync(left, right)
    vaults.path_b.write_bytes(vaults.path_b.read_bytes() + b"external change")

    with pytest.raises(KeepassError, match="changed on disk"):
        apply_database_sync(left, right, plan, vaults.backups)

    # Both originals still need a user-managed recovery; sync must not replace A.
    assert len(Keepass(vaults.path_a, PASSWORD_A).entries()) == 1
    assert not vaults.backups.exists()


def test_backups_are_private_copies_of_both_databases(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.path_a.chmod(0o600)
    vaults.path_b.chmod(0o640)
    original_a, original_b = vaults.path_a.read_bytes(), vaults.path_b.read_bytes()
    vaults.add("a", "A only", "alice", "secret")
    original_a = vaults.path_a.read_bytes()

    left, right = vaults.pair()
    result = apply_database_sync(left, right, plan_database_sync(left, right),
                                 vaults.backups)

    assert len(result.backups) == 2
    assert {p.read_bytes() for p in result.backups} == {original_a, original_b}
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in result.backups)
    assert vaults.backups.stat().st_mode & 0o777 == 0o700


def test_both_files_are_saved_when_only_one_receives_entries(tmp_path):
    vaults = VaultPair(tmp_path)
    vaults.add("a", "A only", "alice", "secret")
    before_a, before_b = vaults.path_a.read_bytes(), vaults.path_b.read_bytes()
    left, right = vaults.pair()

    apply_database_sync(left, right, plan_database_sync(left, right),
                        vaults.backups)

    assert vaults.path_a.read_bytes() != before_a
    assert vaults.path_b.read_bytes() != before_b
    assert len(list(vaults.backups.iterdir())) == 2


def test_same_resolved_database_path_is_rejected(tmp_path):
    vaults = VaultPair(tmp_path)
    left, right = vaults.pair()
    right.path = left.path / ".." / left.path.name
    plan = plan_database_sync(left, right)
    plan.add_to_a.append(next(iter(left.entries().values()), None))

    with pytest.raises(KeepassError, match="paths must be different"):
        apply_database_sync(left, right, plan, vaults.backups)
