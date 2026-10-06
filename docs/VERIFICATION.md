# Verification

2026-10-06, Windows local execution. Python 3.14, OAuthLib 4.0.0, requests 2.34.2, cryptography 50.0.2, SQLite and Flask 3.1.3.

- 33 tests passed, no failures/skips, about 12 seconds. Includes real loopback HTTP, wrong PKCE, callback/state replay, concurrent refresh callers, lost response after rotation, actual child process exit after durable claim and late completion fencing.
- Ruff lint/format checks passed. Source distribution and wheel built successfully.
- Five-stage demonstration executed; evidence/report.json and .html contain observed sanitized results.
- Chromium 1280×900 and 390×900: five stages, keyboard detail expansion, no page errors, no horizontal overflow, zero automated WCAG A/AA axe violations. Screenshot reviewed visually. Video shows the generated captured report, not a live external vendor integration.

## Remote CI — verified

[GitHub Actions run 37414077730](https://github.com/Hadezu/oauth-connection-recovery/actions/runs/37414077730) completed **success** on 2026-10-06. Tested code/test commit: `ba4379f8350c34dbb7960173640c9851f7170d8a`.

- Ubuntu / Python 3.12: frozen dependencies, lint, formatting, full tests, fresh HTTP demonstration and package build passed.
- Ubuntu / Python 3.14: same checks passed.
- Separate Chromium job: freshly generated report at desktop/mobile widths, keyboard expansion, no page errors/overflow passed.
- JUnit, report, wheels/source archive and browser screenshots are downloadable from the run artifacts.

Later documentation-only reconciliation does not change tested code. No production website or external vendor account was used.

Not verified: a physical mobile device, real third-party platform, production throughput, external identity approval, managed key rotation or a security audit. Only original fixture accounts were used; no buyer was contacted.
