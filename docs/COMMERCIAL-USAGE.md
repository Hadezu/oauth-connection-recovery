# Prepared copy — not published to the portfolio

## EN page blurb

**OAuth connection recovery.** An independent working example of authorization with PKCE, encrypted token storage and controlled renewal. It demonstrates what happens when a provider rotates a refresh token but its response is lost, and how explicit reconnection restores access. Local synthetic provider; not a client deployment or approved vendor connector.

Placement: existing `/en/services/api-integration` or secondary evidence from `/en/data-bridge`. No new service category required.

## PL page blurb

**Odzyskiwanie połączenia OAuth.** Niezależny działający przykład autoryzacji z PKCE, szyfrowanego przechowywania tokenów i kontrolowanego odnawiania dostępu. Pokazuje utratę odpowiedzi po rotacji tokenu oraz ponowną autoryzację. Lokalny dostawca testowy i dane syntetyczne; nie jest wdrożeniem klienta ani zatwierdzonym konektorem konkretnej platformy.

## Short relevant email line

I built a [working OAuth recovery example](https://github.com/Hadezu/oauth-connection-recovery) covering encrypted token storage and lost refresh responses against a local test provider. How does your integration currently handle a connection that needs reauthorization?

Use after observing a relevant OAuth/renewal requirement; do not imply the recipient has this defect. No email was sent.

## Proves

- Implementation of a bounded OAuth client lifecycle using real protocol dependencies and HTTP.
- PKCE/state checks, encrypted persistent storage and explicit token-rotation failure handling.
- Durable refresh ownership, stale completion protection, tested reconnection and inspectable evidence.

## Does not prove

- Meta App Review, Google verification, HubSpot/QuickBooks/other live account integration.
- Production OAuth security audit, cryptographic design expertise, enterprise identity or OIDC.
- Social metrics, ETL/scheduler operation, multi-region reliability or client delivery history.
- Full suitability for the source buyer role; only the demonstrated subtask.
