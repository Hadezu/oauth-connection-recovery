# Architecture and failure contract

`Connections → requests HTTP → Flask adapter → OAuthLib Server → synthetic resource`

`Connections → SQLite (encrypted vault + state/version + event journal)`

## Why these parts

OAuthLib supplies real authorization-code/refresh-grant validation including PKCE. A fake token-return function would not demonstrate that boundary. The provider adapter is intentionally disposable: no account service, password store, real consent or external integration.

SQLite uses `BEGIN IMMEDIATE` for short claim/completion transactions. The HTTP call happens **outside** the transaction. REFRESHING is committed first, so another process cannot send the same refresh grant. This is a single-host file-backed design, not a distributed database or high-throughput architecture. Contenders receive a controlled not-ready outcome; there is no hidden waiting queue.

Fernet provides authenticated encryption, using a key passed separately from the database. The encrypted envelope also contains the tenant identifier, so moving ciphertext between tenant rows is rejected. This does not stop a trusted caller from supplying another tenant identifier: the hosting application must authenticate/authorize the caller. Demo keys exist only in memory; loss of a key requires reconnection. Managed key storage/rotation is outside this proof.

## State transitions

AUTHORIZING → EXCHANGING → CONNECTED → REFRESHING → CONNECTED

EXCHANGING / REFRESHING → UNKNOWN (timeout, malformed response, unexpected scope, 5xx)

EXCHANGING / REFRESHING → RECONNECT (provider invalid_grant)

UNKNOWN / RECONNECT → AUTHORIZING (explicit new authorization)

State expires after ten minutes and is consumed before exchanging the one-use code. A crash during code exchange also requires reconnecting. After sixty seconds an abandoned in-flight operation may be explicitly recovered to UNKNOWN; it is never automatically replayed. Recovery increments the version to fence a late completion. Time is the local host clock: production deployment must use reliable clocks and suitable timeout policy.

A version fence protects **local state**, not an in-flight provider request. A delayed old request may still rotate a provider token, but cannot overwrite a newer local connection. No exactly-once claim is made across HTTP and the vault.

## Failure policy

Even an HTTP 503 is conservatively ambiguous. The tool does not assume an unknown provider failed before consuming a refresh token. This trades automatic availability for bounded behavior; a real provider may permit a more specific recovery path.

Successful token responses require bearer type, finite integer lifetime, expected scope and nonempty access/refresh tokens. No silent token coercion. Revoked access detected by `/records` currently returns a controlled resource error; automatic reauthorization on resource 401 is not implemented. This is distinct from invalid_grant during renewal.

## Trust and network boundaries

Loopback origin is constructor-configured, not user-selected. Redirect following is disabled for token/resource requests. No arbitrary URL fetcher, production credentials or provider bodies in reports. Public-client Authorization Code + PKCE is demonstrated; confidential-client secrets, OIDC identity validation, token revocation endpoint and vendor-specific API approvals are not.

The provider is single-threaded and transient; vault concurrency tests use multiple client threads/processes. SQLite rollback/audit behavior is tested; disk-full, OS power loss, multi-host locking and sustained load are not.

Primary references: [OAuthLib provider contract](https://oauthlib.readthedocs.io/en/latest/oauth2/server.html), [validator hooks](https://oauthlib.readthedocs.io/en/latest/oauth2/validator.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html). These inform design; this is not a compliance certification.
