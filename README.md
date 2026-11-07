# pwsync

[![CI](https://github.com/dulguunb/pwsync/actions/workflows/ci.yml/badge.svg)](https://github.com/dulguunb/pwsync/actions/workflows/ci.yml)

Two-way password sync between a **KeePassXC** `.kdbx` database and a
**Bitwarden** vault.

- Bitwarden is reached through the official [`bw` CLI](https://bitwarden.com/help/cli/) —
  no API keys are handled by this tool.
- The `.kdbx` file is read and written with [pykeepass](https://github.com/libkeepass/pykeepass).
- Matching is recorded in a private state file; nothing is ever re-created
  blindly, and deletions are opt-in.
- Secrets are never written to the state file, logs, or backups other than the
  vault snapshots the backups are made of.

## Install

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
cd pwsync
uv sync
uv run pwsync --help
```

`bw` must be installed and logged in (`bw login`).

**No `.kdbx` yet?** pwsync never invents a vault silently, but it can create an
empty one for you — the next sync then fills it from Bitwarden:

```bash
uv run pwsync init --database ~/new.kdbx --create-database
```

Pointing at a path that does not exist is an error (`exit 2`) listing that
command, so a typo in `database = …` can never look like an empty vault. If the
chosen vault is missing, nothing is written anywhere.

## Configure

```bash
uv run pwsync init          # writes ./pwsync.toml
$EDITOR pwsync.toml
```

```toml
[keepass]
database = "~/Passwords.kdbx"
root_group = ""             # optional: sync only this group subtree

[bitwarden]
binary = "bw"

[sync]
conflict = "newest"         # newest | bitwarden | keepassxc
deletes = "ignore"          # ignore | propagate
```

Only the Bitwarden session comes from the environment; the KeePass master
password is **prompted for** and never touches it:

```bash
export BW_SESSION="$(bw unlock --raw)"   # bw's own mechanism
uv run pwsync diff                       # asks for the KeePass master password
```

### Where the KeePass password comes from

In order of precedence:

| Source | When |
| --- | --- |
| `--kdbx-password-file PATH` | unattended runs; keep the file at mode 0600 |
| `--kdbx-password-env NAME` | unattended runs, when you explicitly name a variable |
| interactive prompt | **the default** — `getpass`, never stored, never exported |

The environment is deliberately **not** consulted by default. Anything in a
process's environment is readable by other processes of the same user through
`/proc/<pid>/environ`, and `export PWSYNC_KDBX_PASSWORD=…` also lands in your
shell history. Only pass `--kdbx-password-env NAME` when a scheduler needs it —
and then prefer a file, or a variable injected by the supervisor rather than
typed into an interactive shell.

> Security note: the official `bw` CLI receives item payloads (including the
> password) as base64 command-line arguments. On a multi-user system where
> untrusted users can inspect running processes, the password is theoretically
> visible to them. Use a private machine or run pwsync with appropriate
> process-list restrictions.


## Two-factor authentication

**Bitwarden account 2FA (TOTP, WebAuthn/passkey, email, Duo)** is handled by
`bw` itself, not by pwsync. `bw login` runs once per device and asks for the
code; afterwards `bw unlock` only needs your master password, and pwsync works
with the resulting `BW_SESSION`. pwsync never sees or stores your 2FA secret.

For unattended runs (cron, systemd timer) an interactive `bw login` is not
possible. Use a **personal API key**, which is exempt from 2FA prompts:

```bash
export BW_CLIENTID='user.xxxxxxxx-…'
export BW_CLIENTSECRET='…'
bw login --apikey
export BW_SESSION="$(bw unlock --raw --passwordenv BW_PASSWORD)"
```

**KeePassXC key file** (password + key file) is supported:

```toml
[keepass]
database = "~/Passwords.kdbx"
keyfile = "~/.config/keepassxc/keyfile"
```

**KeePassXC YubiKey challenge-response is not supported.** pykeepass builds the
composite key from a password and/or key file only, so a database protected by a
YubiKey challenge-response cannot be opened — export or re-save it with a master
password before syncing.

**TOTP secrets stored on entries** (Bitwarden login TOTP ↔ KeePassXC `otp`
field) sync in both directions, so your one-time codes keep working whichever
vault you open.

Bitwarden stores a TOTP as either a full `otpauth://` URI or a bare base32
seed, while KeePassXC only generates codes from a URI — it stores a bare seed
but silently ignores it. pwsync therefore canonicalises every value to an
`otpauth://` URI, which also keeps the two sides' content hashes comparable.
A seed that Bitwarden held bare is rewritten once as a URI on the first sync
that touches that item; the secret, period and digit count are unchanged.

Set `totp = false` under `[sync]` to leave each vault's TOTP alone; the rest of
the entry still syncs.

## Use

```bash
uv run pwsync status        # vault connection, link and tombstone counts
uv run pwsync diff          # show the plan; writes nothing
uv run pwsync apply         # write the plan (backs up first)
uv run pwsync apply --dry-run
```

Exit codes: `0` success, `1` pending work for `diff` (like `git diff --exit-code`)
or write errors, `2` configuration or connection problems.

## What maps to what

| Bitwarden           | KeePassXC                          |
| ------------------- | ---------------------------------- |
| login item name     | entry title                        |
| login username      | user name                          |
| login password      | password                           |
| first URI           | URL                                |
| notes               | notes                              |
| login TOTP          | `otp` field                        |
| text/hidden fields  | string custom properties           |
| folder name         | group path, joined by `/`          |

Only Bitwarden **login** items are synced; secure notes, cards and identities
are ignored. Bitwarden folders are flat, so a nested KeePass group such as
`Personal/Email` is stored as one folder literally named `Personal/Email`.

## How changes are detected

Each link stores the content hash that both sides had after the last successful
write. On every run:

- one side changed → that side wins and updates the other;
- both sides changed → conflict: `newest` compares `revisionDate` vs the
  entry's modification time, otherwise `--prefer bitwarden|keepassxc` decides;
  with no clear winner the run reports the conflict and writes nothing;
- an entry exists on one side only → it is created on the other, unless it is
  tombstoned by a previous deletion;
- an entry disappeared on one side → reported (`deletes = "ignore"`, the
  default) or deleted on the other (`--deletes propagate`).

Bitwarden happily holds two logins with the same name *and* username;
pykeepass refuses to create a second one in the same group. pwsync mirrors the
duplicate instead of failing, because the link table — not the title — is what
identifies an entry. Two identical Bitwarden items therefore become two
identical KeePass entries, both tracked separately.

Matching of entries that are not linked yet is heuristic: equal title and
username, unique on both sides. Ambiguous matches are reported and never
guessed. Use `pwsync link --bw-id … --keepass-uuid …` to link manually.

## Safety

- `diff` and `apply --dry-run` never write.
- Every write run snapshots the encrypted `.kdbx` file to
  `~/.local/state/pwsync/backups/<timestamp>/` (mode 0600). Bitwarden has its own
  server-side trash and history, so no plaintext vault export is kept locally.
- The `.kdbx` file is written atomically and the write is refused if the file
  changed on disk since it was read.
- A lock file prevents two syncs from running at once; it is created 0600 inside
  a 0700 state directory.
- pwsync warns if the `.kdbx` is readable by other users (`chmod 600` it). The
  file is always encrypted, but a world-readable vault invites an offline
  brute-force attempt.
- Deletions are never propagated unless you ask for it.

## Not supported (yet)

Passkeys, attachments, Bitwarden organizations/collections, entry history and
custom-field ordering. `bw` is called once per changed item, so a large first
sync is slow.
