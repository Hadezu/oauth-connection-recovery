# Third-party software and our contribution

This is an original integration harness using dependencies, not an attributed fork of a complete application. No upstream source is copied into our code. The upstream packages and their authors retain ownership.

- [OAuthLib](https://github.com/oauthlib/oauthlib), OAuthLib contributors: BSD-3-Clause. Owns OAuth protocol processing, grant and PKCE validation.
- [cryptography](https://github.com/pyca/cryptography), Python Cryptographic Authority: Apache-2.0 OR BSD-3-Clause. Owns Fernet authenticated encryption.
- [Flask](https://github.com/pallets/flask) / Werkzeug, Pallets contributors: BSD-3-Clause. HTTP adapter and loopback server.
- [Requests](https://github.com/psf/requests), Requests contributors: Apache-2.0. HTTP client.
- pytest: MIT; Ruff: MIT; setuptools: MIT; build: MIT; GitHub Actions retain their own upstream licences.

The resolved package versions are in `requirements.lock`. Installed distributions retain their full notices. Original files by Ivan Matiushkin with Codex: the durable lifecycle/vault, local provider adapter/fault controls, scenario tests, report renderer and case study. Compatible permissive dependency terms allow this MIT-licensed integration; no upstream endorsement is claimed.
