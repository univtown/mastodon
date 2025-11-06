# Security Policy (UnivTown Mastodon)

If you have found a security vulnerability that is not present in the latest `main` branches of vanilla Mastodon, glitch-soc or Chuckya, you can report it by sending mail to <admin@univ.town>. Please do **not** report these issues in public spaces, as this may expose UnivTown Mastodon users to increased and unnecessary risk.

As UnivTown Mastodon is purely rolling-release unlike Mastodon or glitch-soc, only the latest commit is actively supported. Please ensure that the vulnerability is present in the latest commit before reporting.

The security policy from upstream is reproduced below.

# Security Policy

If you believe you've identified a security vulnerability in Mastodon (a bug that allows something to happen that shouldn't be possible), you can either:

- open a [GitHub security issue on the Mastodon project](https://github.com/mastodon/mastodon/security/advisories/new)
- reach us at <security@joinmastodon.org>

You should _not_ report such issues on public GitHub issues or in other public spaces to give us time to publish a fix for the issue without exposing Mastodon's users to increased risk.

## Scope

A "vulnerability in Mastodon" is a vulnerability in the code distributed through our main source code repository on GitHub. Vulnerabilities that are specific to a given installation (e.g. misconfiguration) should be reported to the owner of that installation and not us.

## Supported Versions

| Version | Supported        |
| ------- | ---------------- |
| 4.4.x   | Yes              |
| 4.3.x   | Yes              |
| 4.2.x   | Until 2026-01-08 |
| < 4.2   | No               |
