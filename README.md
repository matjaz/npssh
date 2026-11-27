# npssh

An SSH agent for macOS that keeps your keys in **NordPass** instead of `~/.ssh`.

- Private keys are stored in NordPass as Secure Notes, in a hidden field (`private_key`, base64).
- `npssh load` pulls them through the official NordPass CLI (`np`) into agent memory, then locks the `np` vault again.
- Nothing is ever written to disk.
- **Every signature needs Touch ID** (or Apple Watch, or your login password as fallback). The prompt shows which process is asking, e.g. `ssh git@github.com … ← git push`.
- Keys drop out of memory after `--ttl` (default 8h), or right away with `npssh lock`.
- Works with plain `ssh`, `git`, `ssh-add -l/-L`, `ssh-keygen -Y sign` (commit signing), scp, rsync and so on.

## Install

```sh
brew tap nordpass/tap https://downloads.npass.app/cli/homebrew-tap.git   # np = official NordPass CLI
brew install nordpass/tap/np matjaz/tap/npssh
```

After `brew upgrade npssh`, run `npssh install` again so the agent restarts on the new version.

Or build from source (Xcode Command Line Tools + Go ≥ 1.24):

```sh
go test ./... && go build -o ~/.local/bin/npssh .   # any stable dir on PATH
```

The tests use a fake Touch ID check, so they never show a prompt.

## Setup

```sh
np signin                     # one-time, opens the browser
npssh install                 # launchd agent; add --approve-ttl 2m to cache approvals
```

Add to `~/.zshrc`:
```sh
export SSH_AUTH_SOCK=~/.npssh/agent.sock
```
Add to the top of `~/.ssh/config`:
```
Host *
  IdentityAgent ~/.npssh/agent.sock
```

## Keys

```sh
npssh generate github                        # new ed25519 straight into NordPass (never on disk)
npssh import   hetzner ~/.ssh/id_ed25519     # existing key → NordPass (read back + verified)
rm -P ~/.ssh/id_ed25519                      # once `npssh load` + a test login work
```

Items are called `SSH <name>`. The list of items to load is kept in `~/.config/npssh/keys`, one title per line; you can edit it by hand. A key with a passphrase is stored as-is, and `load` asks for the passphrase.

## Daily use

```sh
npssh load            # master password if np is locked, loads keys, runs `np lock`
git push              # → Touch ID prompt
npssh list            # or ssh-add -l
npssh lock            # wipe keys from memory
```

`load` asks for your NordPass **master password**, not Touch ID: the NordPass CLI can only be unlocked with it. Touch ID comes later, each time ssh or git actually uses a key. To type the master password less often, load for longer (`npssh load --ttl 24h`), or skip re-locking with `--keep-unlocked`, though then any process running as you can read the vault through `np`.

## No Touch ID prompt?

Every approval and denial is logged in `~/.npssh/agent.log`. If a login doesn't show up there, ssh never asked the agent to sign:

- **The server doesn't know the key.** ssh only asks for a signature after the server accepts the public key. Add the output of `ssh-add -L | grep 'SSH <name>'` to GitHub, or to the server's `~/.ssh/authorized_keys`. A `user@host's password:` prompt in the terminal is the server's own password login, not npssh.
- **ssh used an old key file.** Keys still in `~/.ssh` (`id_ed25519`, `id_rsa`, …) are tried after the agent's keys, and with `UseKeychain yes` they log in without asking anything. Remove them once the NordPass keys work.

`ssh -v git@github.com 2>&1 | grep -E 'Offering|Server accepts|Authenticated'` shows which keys ssh offered and which one the server took.

A macOS dialog asking for your **login password** is npssh's prompt when Touch ID isn't available, for example with the lid closed and no Touch ID keyboard, or after too many failed fingerprint attempts. The password approves the signature just as Touch ID would.

## Git commit signing

```sh
git config --global gpg.format ssh
git config --global user.signingkey "key::$(ssh-add -L | grep 'SSH github')"
git config --global commit.gpgsign true
```

## Notes

- Log file: `~/.npssh/agent.log`. It records every approval and denial, with the requesting process.
- `--approve-ttl 0` (the default) asks every time. A longer TTL means fewer prompts, but any process can use the key during that window.
- The agent accepts `ssh-add`, so you can still add file-based keys. They also get the Touch ID gate.
- Checked against NordPass CLI 1.0.0. `generate` and `import` unlock the vault first, refuse to create a second `SSH <name>` item, and read the stored key back, failing loudly if it doesn't round-trip.
- `npssh version` prints the installed version.
- Uninstall: `npssh uninstall` (stops and removes the agent), then `brew uninstall npssh`.

## Releasing

```sh
git tag v0.2.0 && git push origin v0.2.0
```

The Release workflow tests, builds a universal macOS binary (`scripts/release.sh`), publishes the GitHub release and commits `Formula/npssh.rb` to [matjaz/homebrew-tap](https://github.com/matjaz/homebrew-tap). That last step needs the `HOMEBREW_TAP_TOKEN` secret (fine-grained token, Contents read/write on the tap); without it the formula is only attached to the release. Running the workflow by hand (Actions › Release › Run workflow) does a test build without publishing anything.
