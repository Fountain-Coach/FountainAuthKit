# FountainAuthKit

> **Your writing is not an account. It is a domain.**

FountainAuthKit is part of a larger idea about publishing: the writer should not have to surrender authority over a work simply because publishing requires machinery.

In the accompanying essay, **[Above the Line — A Strategy for Author-Controlled Publishing in the Age of AI](Docs/above-the-line-strategy.md)**, we argue that publishing is becoming infrastructure. A manuscript is no longer only a file handed to an institution for processing. It can become a domain that produces and maintains its own public forms—website, edition, catalogue information, excerpts, translations and whatever comes next—while the author remains responsible for the work.

FountainAuthKit answers one practical question inside that model:

**Who is allowed to act for this writing domain?**

## Why this exists

Most online products begin with an account.

You create a username, sign in to somebody else’s service, and the service becomes the place where your identity and permissions live. That can be perfectly appropriate for many products. But it is a poor foundation for a publishing system whose central promise is author sovereignty.

A writing domain should be able to say, in effect:

> This is my domain. These are the people and tools I recognize. This is what each of them may do. This permission belongs here, not to whichever application happens to be open today.

FountainAuthKit provides that authority boundary.

Reframe may present the interface. An identity provider may confirm who a person is. An artificial-intelligence service may perform work. A web server may carry requests. A domain-name provider may make the address reachable.

None of those things becomes the owner of the writing domain merely by providing a service.

That distinction is the point.

## Authentication is not ownership

Being able to prove who you are is **authentication**.

Being allowed to perform a particular action is **authorization**.

FountainAuthKit deliberately keeps those two things separate.

A Google, Apple or other sign-in can potentially tell a writing domain, “this person has successfully identified themselves.” It does not thereby gain the right to decide what that person may publish, inspect, change or delegate.

The writing domain makes that decision.

A permission is therefore narrow and explicit. It can name a particular resource, a particular capability and a particular lifetime. Unknown domains, clients, resources and capabilities fail closed rather than quietly falling back to a global administrator.

## SecretStore: keeping secrets out of the wrong places

FountainAuthKit uses the public Fountain Coach library **[swift-secretstore](https://github.com/Fountain-Coach/swift-secretstore)** for private signing-key custody.

The name can sound misleading if it is read as “a store that collects everybody’s secrets.” It means the opposite.

SecretStore exists so that secret material does **not** have to be scattered through application code, Git repositories, configuration files, logs, receipts or authorization records. Its job is to put a boundary around sensitive material and let the host choose the appropriate custody mechanism.

FountainAuthKit knows a key by a non-secret reference. The private key itself remains behind SecretStore’s custody boundary. FountainAuthKit’s durable authorization state contains no private signing-key bytes, no access-token bearer values and no raw authorization codes.

This is not a system for harvesting secrets. It is a system for reducing where secrets can appear.

## What happens in ordinary language

Imagine a writer called Mira.

Mira owns a writing domain. Reframe is the application she happens to use to work with it.

Mira opens Reframe and identifies herself. The identity service proves that she is Mira. FountainAuthKit still does not assume that every action is permitted.

Mira approves a narrowly defined request: Reframe may inspect the host description for this particular domain for a short period of time.

FountainAuthKit issues a signed grant for exactly that purpose.

The protected resource checks the grant before doing anything. The host itself still owns the actual capability. Evidence can record that an authorization happened without retaining the bearer credential that made it usable.

Later, the grant expires or is revoked. It stops working.

If the signing key is rotated, old grants remain verifiable only for a bounded overlap period. If a key is compromised, it stops being trusted immediately. Recovery creates a fresh key rather than reviving compromised material.

The important part is not the cryptography. It is the distribution of authority:

**the writer’s domain remains the place where permission becomes meaningful.**

## Why this belongs in an author-controlled publishing system

The argument in *Above the Line* is not that machines should become authors. It is that machinery can take over more of the execution around authorship while human authority becomes more explicit.

FountainAuthKit applies that same principle to identity and permission.

We do not want an application account to become the hidden owner of a writer’s work simply because the application happens to provide the user interface.

We want the domain to remain governable and portable.

That matters if a writer changes applications. It matters if Reframe changes. It matters if an external identity provider disappears. It matters if one domain is eventually inherited, transferred, archived or operated by a different host.

The authority should survive changes in machinery.

That is what “your writing is not an account” means.

## What FountainAuthKit is not

FountainAuthKit is not a social-login company, a password database or a central Fountain Coach account system.

It is not an OpenID Connect provider.

It does not claim that a public Fountain Coach authorization service is already operating on the internet.

It does not make Reframe, an artificial-intelligence provider, a web server, a domain-name provider or SecretStore the owner of the writing domain.

It is a reusable Swift package that provides the authorization rules and executable contracts from which such a writer-owned service can be built.

## Public by design

The first public release is **v0.1.0**.

The code is public because an authority boundary should be inspectable. The writer should not have to trust a slogan saying that permissions, keys and credentials are handled safely; the implementation and its acceptance scenarios can be examined.

The scenario matrix covers domain isolation, client admission, authorization codes, resource and capability binding, revocation, evidence, host admission, adversarial refusal and signing-key lifecycle.

The package’s release tests include restart recovery, replay refusal, concurrent single-use authorization codes, cross-domain isolation, key rotation, retirement, compromise and recovery.

The exact acceptance record is in **[Scenario/evidence/acceptance-report.md](Scenario/evidence/acceptance-report.md)**.

## For implementers

FountainAuthKit is a Swift package.

```swift
.package(
    url: "https://github.com/Fountain-Coach/FountainAuthKit.git",
    from: "0.1.0"
)
```

Its first profile uses Authorization Code with Proof Key for Code Exchange (PKCE), resource- and capability-bound short-lived signed grants, Ed25519 signatures, restart-safe domain-partitioned authority state and SecretStore-backed signing-key custody.

HTTP is an adapter, not the authority. Domain-name service, certificate management and edge routing are separate capabilities. A protected resource validates a grant before dispatch, and the host continues to own the host capability.

To verify the package locally:

```sh
swift test
./Scripts/secret-shape-scan.sh
```

For the conceptual context, start with **[Above the Line](Docs/above-the-line-strategy.md)**. For the technical authority map, see **[AUTHORITY.md](AUTHORITY.md)**. For the current release evidence, see **[the acceptance report](Scenario/evidence/acceptance-report.md)**.
