import XCTest
import Crypto
import SecretStore
@testable import FountainAuthKit

final class FountainAuthKitTests: XCTestCase {
    func testScenarioProjectionIsCheckedAndBounded() throws {
        let scenarioURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Scenarios/authorization-boundary.json")
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: scenarioURL)) as? [String: Any])
        XCTAssertEqual(object["instrument"] as? String, FountainAuthInstrument.identity)
        XCTAssertEqual((object["terminalPredicates"] as? [String])?.count, 7)
        XCTAssertTrue((object["claimBoundary"] as? String)?.contains("no production issuer") == true)
        XCTAssertEqual(FountainAuthInstrument.beginTopic, "fountaincoach/authorization.begin")
        XCTAssertEqual(FountainAuthInstrument.beginResultTopic, "fountaincoach/authorization.begin.result")
    }

    private func server(evidenceLedger: (any FountainAuthGrantEvidenceLedger)? = nil) async throws -> (FountainAuthAuthorizationServer, FountainAuthMemoryKeyStore, URL, URL) {
        let issuer = URL(string: "https://auth.example.test")!
        let resource = URL(string: "https://resource.example.test/mcp")!
        let metadata = try FountainAuthServerMetadata(
            issuer: issuer,
            authorizationEndpoint: issuer.appendingPathComponent("oauth/authorize"),
            tokenEndpoint: issuer.appendingPathComponent("oauth/token"),
            jwksURI: issuer.appendingPathComponent(".well-known/jwks.json"),
            scopesSupported: ["estate.inspect"])
        let keys = try FountainAuthMemoryKeyStore()
        let server = try FountainAuthAuthorizationServer(metadata: metadata, keyStore: keys,
                                                         evidenceLedger: evidenceLedger)
        try await server.register(FountainAuthClientRegistration(
            clientID: "native-client", redirectURIs: [URL(string: "http://app.localhost/callback")!]))
        return (server, keys, issuer, resource)
    }

    func testMetadataAndProtectedResourceAreSeparateDiscoverableContracts() async throws {
        let (_, _, issuer, resource) = try await server()
        let protectedMetadata = try FountainAuthProtectedResourceMetadata(
            resource: resource, authorizationServer: issuer, scopesSupported: ["estate.inspect"])
        XCTAssertEqual(protectedMetadata.authorizationServers, [issuer])
        XCTAssertEqual(FountainAuthInstrument.identity, "fountaincoach.authorization@0.1.0")
    }

    func testPKCEResourceBoundGrantIsOneTimeAndValidatesScope() async throws {
        let (server, _, _, resource) = try await server()
        let verifier = "a-secure-native-client-verifier-value-1234567890"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client", redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"], state: "state-1",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "corr-1", expiresAt: Date().addingTimeInterval(60))
        let code = try await server.begin(request, subjectReference: "subject:owner-1",
                                          authenticationMechanism: "fixture-human-consent", decision: .approved)
        let token = try await server.redeem(code: code.value, clientID: request.clientID,
                                            redirectURI: request.redirectURI, verifier: verifier, resource: resource)
        let grant = try await server.validate(token, resource: resource, requiredScope: "estate.inspect")
        XCTAssertEqual(grant.subjectReference, "subject:owner-1")
        do {
            _ = try await server.redeem(code: code.value, clientID: request.clientID,
                                        redirectURI: request.redirectURI, verifier: verifier, resource: resource)
            XCTFail("authorization code replay must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .unknownCode)
        }
    }

    func testWrongResourceRedirectPKCEAndRevocationFailClosed() async throws {
        let (server, _, _, resource) = try await server()
        let otherResource = URL(string: "https://other.example.test/mcp")!
        let verifier = "another-secure-native-client-verifier-value-1234567890"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client", redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"], state: "state-2",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "corr-2", expiresAt: Date().addingTimeInterval(60))
        let code = try await server.begin(request, subjectReference: "subject:owner-1",
                                          authenticationMechanism: "fixture-human-consent", decision: .approved)
        do {
            _ = try await server.redeem(code: code.value, clientID: request.clientID,
                                        redirectURI: request.redirectURI, verifier: verifier, resource: otherResource)
            XCTFail("resource mismatch must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .resourceMismatch)
        }

        let second = try await server.begin(request, subjectReference: "subject:owner-1",
                                            authenticationMechanism: "fixture-human-consent", decision: .approved)
        let token = try await server.redeem(code: second.value, clientID: request.clientID,
                                            redirectURI: request.redirectURI, verifier: verifier, resource: resource)
        try await server.revoke(token)
        do {
            _ = try await server.validate(token, resource: resource, requiredScope: "estate.inspect")
            XCTFail("revoked token must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }
    }

    func testKeyRotationRetainsVerificationForPermittedInflightToken() async throws {
        let (server, keys, _, resource) = try await server()
        let verifier = "rotation-verifier-value-123456789012345678901234"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client", redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"], state: "state-rotation",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "corr-rotation", expiresAt: Date().addingTimeInterval(60))
        let firstCode = try await server.begin(request, subjectReference: "subject:owner-1",
                                               authenticationMechanism: "fixture-human-consent", decision: .approved)
        let firstToken = try await server.redeem(code: firstCode.value, clientID: request.clientID,
                                                 redirectURI: request.redirectURI, verifier: verifier, resource: resource)
        try await keys.rotate(keyID: "auth-test-2")
        do {
            _ = try await server.validate(firstToken, resource: resource, requiredScope: "estate.inspect")
        } catch {
            XCTFail("permitted in-flight token must remain valid across key rotation: \(error)")
        }
    }

    func testGrantEvidenceNeverContainsBearerCredential() async throws {
        let (server, _, _, resource) = try await server()
        let verifier = "evidence-verifier-value-12345678901234567890"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client", redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"], state: "state-3",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "corr-3", expiresAt: Date().addingTimeInterval(60))
        let code = try await server.begin(request, subjectReference: "subject:owner-1",
                                          authenticationMechanism: "fixture-human-consent", decision: .approved)
        let encoded = String(decoding: try JSONEncoder().encode(code.evidence), as: UTF8.self)
        XCTAssertFalse(encoded.contains(code.value))
        XCTAssertFalse(encoded.contains("privateKey"))
    }

    func testSecretStoreKeyStoreRotatesWithoutExposingPrivateMaterial() async throws {
        let store = TestSecretStore()
        let firstPrivateKey = Curve25519.Signing.PrivateKey()
        let first = try FountainAuthSecretKeyReference(keyID: "auth-secret-1", account: "key-1")
        try store.storeSecret(firstPrivateKey.rawRepresentation, for: first.account)
        let keys = try FountainAuthSecretStoreKeyStore(store: store, active: first)
        let activeKey = try await keys.activeSigningKey()
        let oldPublicKey = activeKey.publicKey

        let second = try FountainAuthSecretKeyReference(keyID: "auth-secret-2", account: "key-2")
        try await keys.rotate(to: second)
        let verification = try await keys.verificationKeys()
        XCTAssertEqual(verification[first.keyID], oldPublicKey)
        XCTAssertNotNil(verification[second.keyID])
        XCTAssertNil(try store.retrieveSecret(for: "missing"))
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(second), as: UTF8.self).contains("private"))
    }

    func testGrantEvidenceLedgerIsIdempotentAndConflictProtected() async throws {
        let (server, _, _, resource) = try await server()
        let verifier = "ledger-verifier-value-123456789012345678901234"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client", redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"], state: "state-ledger",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "corr-ledger", expiresAt: Date().addingTimeInterval(60))
        let code = try await server.begin(request, subjectReference: "subject:owner-1",
                                          authenticationMechanism: "fixture-human-consent", decision: .approved)
        let ledger = FountainAuthMemoryGrantEvidenceLedger()
        try await ledger.append(code.evidence)
        try await ledger.append(code.evidence)
        let stored = try await ledger.evidence(for: code.evidence.authorizationEventID)
        XCTAssertEqual(stored, code.evidence)

        let conflict = FountainAuthGrantEvidence(
            issuer: code.evidence.issuer, authorizationEventID: code.evidence.authorizationEventID,
            subjectReference: "subject:other", clientID: code.evidence.clientID, resource: resource,
            requestedScope: code.evidence.requestedScope, grantedScope: code.evidence.grantedScope,
            authorizedAt: code.evidence.authorizedAt, expiresAt: code.evidence.expiresAt,
            authenticationMechanism: code.evidence.authenticationMechanism,
            policyVersion: code.evidence.policyVersion, state: code.evidence.state,
            sessionCorrelationID: code.evidence.sessionCorrelationID)
        do {
            try await ledger.append(conflict)
            XCTFail("authorization-event reuse with different evidence must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .evidenceConflict)
        }
    }

    func testRedeemAppendsIssuedEvidenceToHostLedgerExactlyOnce() async throws {
        let ledger = FountainAuthMemoryGrantEvidenceLedger()
        let (server, _, _, resource) = try await server(evidenceLedger: ledger)
        let verifier = "ledger-hook-verifier-value-123456789012345678901234"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client", redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"], state: "state-ledger-hook",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "corr-ledger-hook", expiresAt: Date().addingTimeInterval(60))
        let code = try await server.begin(request, subjectReference: "subject:owner-1",
                                          authenticationMechanism: "fixture-human-consent", decision: .approved)
        let token = try await server.redeem(code: code.value, clientID: request.clientID,
                                            redirectURI: request.redirectURI, verifier: verifier, resource: resource)
        let stored = try await ledger.evidence(for: token.evidence.authorizationEventID)
        XCTAssertEqual(stored, token.evidence)
        XCTAssertEqual(stored?.state, "issued")
        let encoded = String(decoding: try JSONEncoder().encode(stored), as: UTF8.self)
        XCTAssertFalse(encoded.contains(token.value))
        XCTAssertFalse(encoded.contains("privateKey"))
    }
}

private final class TestSecretStore: SecretStore, @unchecked Sendable {
    private var values: [String: Data] = [:]

    func storeSecret(_ secret: Data, for key: String) throws { values[key] = secret }
    func retrieveSecret(for key: String) throws -> Data? { values[key] }
    func deleteSecret(for key: String) throws { values.removeValue(forKey: key) }
}


extension FountainAuthKitTests {
    private func isolatedServer(issuer: URL) async throws -> (FountainAuthAuthorizationServer, FountainAuthMemoryKeyStore, URL) {
        let resource = URL(string: "https://mcp." + issuer.host!.replacingOccurrences(of: "auth.", with: ""))!
        let metadata = try FountainAuthServerMetadata(
            issuer: issuer,
            authorizationEndpoint: issuer.appendingPathComponent("oauth/authorize"),
            tokenEndpoint: issuer.appendingPathComponent("oauth/token"),
            jwksURI: issuer.appendingPathComponent(".well-known/jwks.json"),
            scopesSupported: [FountainAuthHostDescribeAdmission.capability])
        let keys = try FountainAuthMemoryKeyStore(keyID: "key-" + issuer.host!)
        let server = try FountainAuthAuthorizationServer(metadata: metadata, keyStore: keys, tokenLifetime: 60)
        try await server.register(FountainAuthClientRegistration(
            clientID: "reframe-native",
            redirectURIs: [URL(string: "http://reframe.localhost/callback")!]))
        return (server, keys, resource)
    }

    private func hostToken(server: FountainAuthAuthorizationServer, resource: URL,
                           suffix: String = "one", now: Date = Date()) async throws -> FountainAuthAccessToken {
        let verifier = "host-describe-verifier-value-12345678901234567890-" + suffix
        let request = try FountainAuthAuthorizationRequest(
            clientID: "reframe-native",
            redirectURI: URL(string: "http://reframe.localhost/callback")!,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-" + suffix,
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource,
            correlationID: "corr-" + suffix,
            expiresAt: now.addingTimeInterval(60))
        let code = try await server.begin(request,
                                          subjectReference: "subject:writer",
                                          authenticationMechanism: "fixture-authentication-adapter",
                                          decision: .approved,
                                          now: now)
        return try await server.redeem(code: code.value,
                                       clientID: request.clientID,
                                       redirectURI: request.redirectURI,
                                       verifier: verifier,
                                       resource: resource,
                                       now: now)
    }

    func testSharedRuntimeResolvesExactDomainAndUnknownDomainFailsClosed() async throws {
        let issuerA = URL(string: "https://auth.writer-a.example")!
        let issuerB = URL(string: "https://auth.writer-b.example")!
        let (serverA, _, _) = try await isolatedServer(issuer: issuerA)
        let (serverB, _, _) = try await isolatedServer(issuer: issuerB)
        let runtime = FountainAuthDomainRuntime()

        try await runtime.admit(issuer: issuerA, authority: serverA)
        try await runtime.admit(issuer: issuerB, authority: serverB)
        let admittedIssuers = await runtime.admittedIssuers()
        XCTAssertEqual(admittedIssuers, [
            "https://auth.writer-a.example",
            "https://auth.writer-b.example"
        ])

        let resolved = try await runtime.authority(for: issuerA)
        let resolvedMetadata = await resolved.metadata
        XCTAssertEqual(resolvedMetadata.issuer, issuerA)

        do {
            _ = try await runtime.authority(for: URL(string: "https://auth.unknown.example")!)
            XCTFail("unknown domain must not fall back to another authority")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidIssuer)
        }
    }

    func testTwoDomainsCannotSubstituteTokensOrKeys() async throws {
        let issuerA = URL(string: "https://auth.writer-a.example")!
        let issuerB = URL(string: "https://auth.writer-b.example")!
        let (serverA, _, resourceA) = try await isolatedServer(issuer: issuerA)
        let (serverB, _, _) = try await isolatedServer(issuer: issuerB)
        let tokenA = try await hostToken(server: serverA, resource: resourceA)

        _ = try await serverA.validate(tokenA, resource: resourceA,
                                       requiredScope: FountainAuthHostDescribeAdmission.capability)

        do {
            _ = try await serverB.validate(tokenA, resource: resourceA,
                                           requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("domain B must not validate a token signed/issued by domain A")
        } catch {
            XCTAssertNotNil(error as? FountainAuthError)
        }
    }

    func testHostDescribeRequiresExactCapabilityAndProducesTypedAdmission() async throws {
        let issuer = URL(string: "https://auth.writer.example")!
        let (server, _, resource) = try await isolatedServer(issuer: issuer)
        let token = try await hostToken(server: server, resource: resource)
        let grant = try await server.validate(token, resource: resource,
                                               requiredScope: FountainAuthHostDescribeAdmission.capability)
        let admission = try FountainAuthHostDescribeAdmission(validatedGrant: grant)
        XCTAssertEqual(admission.resource, resource)
        XCTAssertEqual(admission.issuer, issuer)

        do {
            _ = try await server.validate(token, resource: resource, requiredScope: "host.mutate")
            XCTFail("ungranted capability must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .scopeMissing("host.mutate"))
        }
    }

    func testUnknownClientAndInvalidPKCEFailClosed() async throws {
        let issuer = URL(string: "https://auth.writer.example")!
        let (server, _, resource) = try await isolatedServer(issuer: issuer)
        let verifier = "pkce-verifier-value-123456789012345678901234567"
        let unknownRequest = try FountainAuthAuthorizationRequest(
            clientID: "unknown-client",
            redirectURI: URL(string: "http://reframe.localhost/callback")!,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-unknown",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource,
            correlationID: "corr-unknown",
            expiresAt: Date().addingTimeInterval(60))
        do {
            _ = try await server.begin(unknownRequest,
                                       subjectReference: "subject:writer",
                                       authenticationMechanism: "fixture-authentication-adapter",
                                       decision: .approved)
            XCTFail("unknown client must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidClient)
        }

        let request = try FountainAuthAuthorizationRequest(
            clientID: "reframe-native",
            redirectURI: URL(string: "http://reframe.localhost/callback")!,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-pkce",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource,
            correlationID: "corr-pkce",
            expiresAt: Date().addingTimeInterval(60))
        let code = try await server.begin(request,
                                          subjectReference: "subject:writer",
                                          authenticationMechanism: "fixture-authentication-adapter",
                                          decision: .approved)
        do {
            _ = try await server.redeem(code: code.value,
                                        clientID: request.clientID,
                                        redirectURI: request.redirectURI,
                                        verifier: verifier + "-wrong",
                                        resource: resource)
            XCTFail("invalid PKCE verifier must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidPKCE)
        }
    }

    func testExpiredAndTamperedTokensFailClosed() async throws {
        let issuer = URL(string: "https://auth.writer.example")!
        let (server, _, resource) = try await isolatedServer(issuer: issuer)
        let issuedAt = Date()
        let token = try await hostToken(server: server, resource: resource, suffix: "expiry", now: issuedAt)

        do {
            _ = try await server.validate(token, resource: resource,
                                           requiredScope: FountainAuthHostDescribeAdmission.capability,
                                           now: issuedAt.addingTimeInterval(120))
            XCTFail("expired token must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenExpired)
        }

        var parts = token.value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        parts[2] = String(parts[2].dropLast()) + (parts[2].last == "A" ? "B" : "A")
        let tampered = FountainAuthAccessToken(value: parts.joined(separator: "."), evidence: token.evidence)
        do {
            _ = try await server.validate(tampered, resource: resource,
                                           requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("tampered signature must fail")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidToken)
        }
    }
}
