# Thimble

Interact with GitHub with multiple agents without getting pricked.

Thimble gives each AI coding agent on a Mac its own GitHub App identity, so the agent never uses your GitHub login. Keys stay out of the agent's reach, tokens refresh themselves, and `gh` and Git fail closed.

A thimble lets you push the needle without getting pricked.

## How it works

- **One GitHub App per agent per organization.** Each App's private key sits in a folder no agent can read.
- **One launchd job** runs every ten minutes. It mints a fresh one-hour installation token for each App whose token is 40 minutes old, signed with that App's own key.
- **Git** gets the token from a credential helper named in each checkout's `.git/config`.
- **`gh`** gets it from `GH_TOKEN`, which a block in `~/.zshenv` sets from the shell's working folder.
- **The folder decides the identity.** If the token can't be read, `gh` and Git fail. They never fall back to your own login.

Thimble is a small set of shell scripts that you can read in one sitting. There is no daemon, and nothing else to install: it uses only tools that come with macOS. Because the identity is keyed on the working folder, it works however the agent is started, from a desktop app or a terminal.

## Status

v0.1 is in progress (#2) and supports macOS only. Installation and usage docs follow in #3.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
