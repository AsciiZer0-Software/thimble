# Security Policy

Thimble is developed by asciiZer0 Software LLC. It handles GitHub App private keys and the tokens minted from them, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

Thimble has not reached 1.0. Security fixes go into the latest release and `main`.

| Version | Supported |
| ------- | --------- |
| Latest release and `main` | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request or discussion for security problems.**

Report privately through either channel:

1. **GitHub private vulnerability reporting:** use the **"Report a vulnerability"** button on this repository's **Security** tab.
2. **Email:** security@asciizer0.com

Please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- Your macOS version, and the agent harness and its sandbox settings if they matter
- What an attacker needs to start with (for example, control of one agent's session) and what they gain (for example, another App's token or key)

**Never include a real private key or token in a report.** Use a synthetic key and a throwaway App, or redact the value.

## What to expect

| Step | Target |
| ---- | ------ |
| Acknowledgement of your report | Within 3 business days |
| Initial assessment and severity | Within 10 business days |
| Fix or mitigation for confirmed issues | Depends on severity; critical issues come first |

We will keep you informed and tell you when a fix ships. With your permission, we are happy to credit you in the release notes.

## Scope

**In scope**

- The scripts in this repository: `thimble`, `git-credential-thimble` and `install`
- What `install` writes: the installed scripts, the launchd job and the `~/.zshenv` block
- Ways for one agent to obtain another App's key or token, or to act as the human, through anything Thimble sets up

**Out of scope**

- Vulnerabilities in GitHub, macOS, `gh`, Git or an agent harness and its sandbox (report these to their vendors)
- Attacks that need root, or the human's own unsandboxed shell
- Social engineering, spam or denial-of-service testing
- Findings from automated scanners without a demonstrated impact

## Safe harbor

We will not pursue legal action against researchers who act in good faith: who use only their own Apps and accounts, avoid accessing other people's data, give us reasonable time to fix an issue before disclosing it, and follow this policy.
