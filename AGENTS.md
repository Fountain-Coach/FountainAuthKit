# Agent law

Treat `GOAL.md` and `AUTHORITY.md` as controlling.

- Preserve authentication / authorization / protected-resource / host / evidence separation.
- Never broaden authority to make a test pass.
- Public native clients do not use embedded client secrets.
- Authorization Code + PKCE S256 is mandatory for the first profile.
- Tokens are short-lived, resource-bound and explicitly capability-scoped.
- Unknown domains, issuers, clients, resources, capabilities and keys fail closed.
- Broad `root`, `all` and unqualified `admin` capability shortcuts are prohibited.
- Private keys, bearer credentials and authorization codes never enter public evidence, fixtures, logs or screenshots.
- In-memory state is fixture-only where restart survival is required.
- Host capability remains host-owned.
- Keep multi-step work and scenario-row status in `PLANS.md`.
- Do not tag or publish a semantic release while an acceptance gate in `Scenario/evidence/acceptance-report.md` is blocked.
