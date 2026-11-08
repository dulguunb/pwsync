# Agent rules for this repository

## Never touch a live vault

pwsync exists to move data between the user's **real** password vaults. An agent
must not operate on them, not even read-only: one stray command can copy secrets
into a transcript, and one stray write can corrupt a database.

Off limits from an agent session:

- every `bw` subcommand — `status`, `unlock`, `login`, `logout`, `sync`, `list`,
  `get`, `create`, `edit`, `delete`, `move`, `export`;
- every `keepassxc-cli` subcommand — `show`, `ls`, `add`, `edit`, `rm`,
  `db-edit`, `db-info`, `db-create`, `export`, `import`, `clip`, `analyze`,
  `attachment-*`;
- running `pwsync` itself against a real configuration (`diff`, `apply`,
  `copy-from-bitwarden-to-keepass`, `import-totp`, `link`), because each opens
  the user's vault and asks for the master password;
- reading a real `.kdbx`, `state.json`, `BW_SESSION`, `BW_PASSWORD`,
  `PWSYNC_KDBX_PASSWORD`, or a Bitwarden data directory by any other route.

If a task seems to need vault access, stop and ask the user to run the command
themselves, and say which command. Offer the flags; let them press Enter.

## What an agent may do

- Edit, run and test the code.
- Run the test suite. It is hermetic by design: `tests/fake_bw.py` stands in for
  the Bitwarden CLI and every database lives in pytest's `tmp_path`, including
  the one test that calls `keepassxc-cli show --totp` on a throwaway vault.
- Build throwaway fixtures in a scratch directory (`.your-check/`, `tmp_path`)
  and delete them afterwards.

## Keeping the suite hermetic

Anything that would make a test read a real vault is a bug in the test:

- point `[bitwarden] binary` at `tests/fake_bw.py`, never at `bw`;
- set `state_file` and `backup_dir` inside `tmp_path` so a run cannot touch
  `~/.local/state/pwsync`;
- never assert on, or print, a value that came from a real vault.

## Talking about the user's data

Do not quote entry titles, usernames, URLs or passwords from a real vault in
commit messages, issues, pull requests, docs or chat. This repository is public;
use a placeholder such as `example.com` instead.
