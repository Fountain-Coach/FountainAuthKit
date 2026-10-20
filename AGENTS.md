# Agent law

## FCIS Goal Fidelity and Non-Invention (mandatory)

Follow the [FCIS founding conduct standard](https://github.com/Fountain-Coach/.github/blob/main/docs/FCIS-Non-Invention-and-Goal-Fidelity.md) before planning or changing scope. The requested observable outcome is fixed. Inspect existing accepted runtime and Git history before designing anything.

**A new blocker is valid only with:** the requested outcome, a reproduced failed operation, an already applicable binding requirement, and the smallest correction with an original-path acceptance test. Missing proof, historical concern, a hypothetical risk or a desired improvement is **not** automatically a blocker.

Do not build alternate authorization, host, transport, storage or test machinery merely because it could be useful. Passing tests of your invention does not establish its necessity. Do not expand the Definition of Done unless the user changes the goal or a demonstrated defect directly invalidates its acceptance. Continue work without repeatedly asking the user to say 'proceed accordingly'. Correct unjustified expansions by reversible cleanup, preserving unrelated work. Respect real security/legal constraints and report completion only with the requested live evidence.

This clause has precedence when interpreting this repository's procedural requirements and proof-bounded development rules.


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
