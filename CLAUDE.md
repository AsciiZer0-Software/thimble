# CLAUDE.md

Repository conventions for all agents, including Claude, live in [AGENTS.md](AGENTS.md). Follow it.

@AGENTS.md

## Working together

- Shawn McCollum, founder of asciiZer0 Software, leads and decides, and merges every pull request. Work with him as a colleague: he brings 26 years of development experience and knows C# well.
- No flattery. Lead with the substance.
- When something would change a decision, say so plainly. Skip the nitpicks.
- Choose models, effort levels and subagents by the model usage guidance in the Pin Cushion repository (`docs/model-usage-guidance.md`). Use Ultracode workflows or the Fable model only when Shawn chooses them.

## Identity

From its checkout under `~/ClaudeWork`, Claude works as the `asciizer0-claude` GitHub App, which was previously called `pincushion-claude`. Commits are authored as `asciizer0-claude[bot]`, branches are `agent/claude/<issue#>-<slug>`, and a `Co-Authored-By` trailer names the model.

At the start of each session, run each of these as its own bare command. If any result is wrong, stop and tell Shawn.

- `gh auth status`: the active account is `asciizer0-claude[bot] (GH_TOKEN)`. An inactive keyring login for Shawn is normal.
- `gh api installation/repositories --jq '.repositories | map(.full_name)'`: includes `AsciiZer0-Software/thimble`.
- `git config --local --get user.name`: `asciizer0-claude[bot]`.
- `git config --local --get-all credential.helper`: an empty line, then the helper.
- `git fetch origin`: succeeds with no prompt.

`gh api user` returns 403 for an App token, so it is not a usable check. An App also can't be assigned to an issue: claim issues with the `agent:in-progress` label and a comment.

## Credentials

- Never read a private key (`*.pem`) or print a token. Never put `GH_TOKEN=…` in front of a command.
- Never run `install` against the real HOME, and never touch launchd or `~/.zshenv`. Shawn installs. Tests always use a temporary HOME.
- Never describe an unfixed vulnerability in a public issue or pull request. Tell Shawn privately.

## Shell habits on this Mac (zsh)

- Give commands absolute paths (`git -C <repo>`, `python3 -I <path>`) rather than `cd` into a subfolder. Pass this rule on in subagent briefs.
- Put multi-line scripts in a file in the scratchpad and run that file. Use `$TMPDIR` for temporary files.
- Write command arguments out in full. zsh doesn't split an unquoted variable into words.
- `gh` and `git push` run outside the sandbox only as bare calls: nothing chained with `;` or `&&`, no `$(…)`, no variable prefix. Anything else stays sandboxed, where `gh` and Git LFS fail TLS. Run `git push origin <branch>` from the repository root.
- In `gh … --jq` filters, build arrays with `map()` rather than `[ … ]`: a `[` with content before `]` is a glob character class, and the read-only `gh` allow rules stop matching.
- The sandbox refuses writes to `.git/config`. Create branches with `git -C <repo> checkout --no-track -b <branch> origin/main` and push without `-u`.
- When a command fails on a sandbox restriction, report the exact path, domain or service to Shawn. Don't work around it.
