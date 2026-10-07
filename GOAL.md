# Goal

FountainAuthKit makes writer-domain authorization a reusable Swift-native capability.

The controlling product promise is:

> **Your writing is not an account. It is a domain.**

A writer-owned domain may operate an authorization authority whose issuer, clients, grants, resources, capabilities, keys and revocation state are logically separate from every other writing domain, even when several domains share one process or host.

The first vertical proof is one public native client using Authorization Code with PKCE to receive one short-lived grant for exactly one protected resource and the read-only capability `host.describe`. The protected resource validates the grant before dispatch, the host owns execution, and retained evidence contains no bearer credential.

Completion requires deterministic refusal of unknown domains, clients, resources, capabilities and keys; two-domain isolation; signing-key lifecycle evidence; restart-safe authority state; and truthful public release evidence.
