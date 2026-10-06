# Buyer need → implemented evidence

Reviewed 2026-10-06. Sources are requirements evidence, not contacted prospects or a claim that these positions remain open.

## Primary buyer evidence

[Backend Developer for OAuth and Social Media Analytics API Integration](https://www.upwork.com/freelance-jobs/apply/Backend-Developer-for-OAuth-and-Social-Media-Analytics-API-Integration_~022088343691184645548/) was publicly readable during this review (listed as posted two months ago). The buyer asks for a bounded OAuth proof of concept, protected token storage, renewal/reconnection and maintainable source/setup documentation. This project addresses those mechanisms. It does **not** supply social metrics, platform approvals or the complete requested portal.

[Multi-tenant dashboard integration requirement](https://www.upwork.com/freelance-jobs/apply/Backend-developer-for-multi-tenant-SaaS-dashboard-Supabase-React-OAuth-integrations_~022097117378203702614/) independently asks for isolated access/refresh credentials and encrypted storage. Our tenant-bound ciphertext and lookup tests are relevant but do not prove a production multi-tenant SaaS.

## Fit with the existing offering

The live `/en/services/api-integration` page was fetched with HTTP 200: one data flow, authentication feasibility, logs, tests and agreed failure handling. The existing Data Bridge page demonstrates flow reliability. This project supplies the missing renewable authorization boundary.

Reviewed public repository inventory: work-portfolio, atomic-crm-import-review, fastapi-webhook-reliability, resilience4j-retry-review, reconciliation-evidence-workbench, operations-approval-desk and llm-extraction-release-gate. PostgreSQL Import Rehearsal is explicitly excluded because another task is implementing it. Their README scope overlaps API/data work, but none provides this OAuth token-lifecycle proof. No existing repository or production website was changed.

## Acceptance before implementation

1. Real OAuthLib code exchange over HTTP with S256 PKCE and one-use state.
2. Tokens encrypted in a persistent local vault, bound to the supplied tenant key.
3. Concurrent access cannot issue duplicate refresh grants.
4. Lost response / malformed output / unexpected scope / 5xx stops in UNKNOWN.
5. Invalid grant requires reauthorization; a new authorization restores access.
6. Durable in-flight state survives process exit; stale completions are fenced.
7. Auditable transitions and downloadable evidence contain no secrets.
8. Repeatable setup, failure tests and independently executed CI.
