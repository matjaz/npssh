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
npssh load            # unlocks np if needed (master password), loads keys, runs `np lock`
git push              # → Touch ID prompt
npssh list            # or ssh-add -l
npssh lock            # wipe keys from memory
```

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
- The `--format`, custom-field and stdin (`-`) behaviour of `np` was taken from NordPass's CLI docs. `import` reads the stored item back and fails loudly if anything doesn't round-trip.
- Uninstall: `npssh uninstall`.

## Releasing

```sh
git tag v0.2.0 && git push origin v0.2.0
```

The Release workflow tests, builds a universal macOS binary (`scripts/release.sh`), publishes the GitHub release and commits `Formula/npssh.rb` to [matjaz/homebrew-tap](https://github.com/matjaz/homebrew-tap). That last step needs the `HOMEBREW_TAP_TOKEN` secret (fine-grained token, Contents read/write on the tap); without it the formula is only attached to the release. Running the workflow by hand (Actions › Release › Run workflow) does a test build without publishing anything.
