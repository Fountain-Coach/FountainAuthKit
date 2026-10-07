# Standards profile

The first profile is OAuth authorization, not an OpenID Connect provider claim.

Normative interoperability references:
- RFC 6749 — OAuth 2.0 Authorization Framework, constrained by current best practice.
- RFC 7636 — Proof Key for Code Exchange (PKCE).
- RFC 8414 — OAuth 2.0 Authorization Server Metadata.
- RFC 9700 — OAuth 2.0 Security Best Current Practice.
- RFC 9728 — OAuth 2.0 Protected Resource Metadata.
- RFC 9207 — Authorization Server Issuer Identification where applicable.
- RFC 8707 — Resource Indicators.
- RFC 7009 — Token Revocation when projected through a public endpoint.
- RFC 7519 / RFC 7515 / RFC 7517 and applicable JOSE registrations for JWT/JWS/JWK use.

Current signed-token profile: Ed25519 signatures exposed as `alg=EdDSA`.

Standards establish interoperability. Fountain governance owns admission, capability vocabulary, evidence and host authority.
