# Scope

This is a hardened, private fork of the CloakBrowser wrapper, run by ~20 AI
agents on one shared Linux box. It exists for **security, stability and account
health on our own orgs' accounts**. It is not an anti-detection tool.

## Non-goals (non-negotiable)

Never add, and remove on sight:

- Captcha solving, or integration with any captcha-solving service.
- Anti-bot / bot-detection bypass or evasion of any kind.
- Automation-signal masking, or "humanized" input intended to look less
  automated.
- Scoring or benchmarking against detection vendors.
- Fingerprint spoofing whose purpose is defeating detection.
- Scraping and bulk actions: mass follows/likes/comments/DMs, account creation,
  multi-account coordination.

## Challenges are a hard stop

A captcha, checkpoint, "unusual activity" notice, "confirm it's you" prompt,
2FA/passkey prompt, rate limit or suspicious-login warning means: **stop the
agent and notify a human.** Never retry, reload, switch profiles, or route
around it.

## What fingerprint work means here

Consistency, not concealment. One stable, truthful identity per profile that
matches the real host — Linux, the real display, the home exit's real timezone
and locale — pinned so the account is not seen as a new device every session.
No rotating identities, no per-site personas.

This is why `get_default_stealth_args()` passes only `--fingerprint=<seed>`:
upstream additionally spoofs a Windows persona on Linux, which contradicts the
real GPU, fonts and display. That is an inconsistency, not a hardening.

## Access rules

- Official APIs first. A browser is the last resort.
- No browser automation on X or LinkedIn.
- Never sign in to Google from an automated browser — use the Google connector.

## Reviewing a change against this file

Ask what a feature is *for*. Sandboxing, per-org encryption keys, proxy-only
egress, profile locking and audit logging are wanted. Anything whose purpose is
to make automation harder to detect is out of scope — remove it rather than
improve it.
