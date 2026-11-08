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
        let admittedIssuers = try await runtime.admittedIssuers()
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
        let originalFirst = parts[2].first!
        parts[2] = String(originalFirst == "A" ? "B" : "A") + parts[2].dropFirst()
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


extension FountainAuthKitTests {
    private func durableMetadata(issuer: URL) throws -> FountainAuthServerMetadata {
        try FountainAuthServerMetadata(
            issuer: issuer,
            authorizationEndpoint: issuer.appendingPathComponent("oauth/authorize"),
            tokenEndpoint: issuer.appendingPathComponent("oauth/token"),
            jwksURI: issuer.appendingPathComponent(".well-known/jwks.json"),
            scopesSupported: [FountainAuthHostDescribeAdmission.capability])
    }

    func testDurableAuthorityStateSurvivesRestartWithoutPersistingBearers() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("authority-state.json")
        let issuer = URL(string: "https://auth.restart.example")!
        let resource = URL(string: "https://mcp.restart.example")!
        let redirect = URL(string: "http://reframe.localhost/callback")!
        let metadata = try durableMetadata(issuer: issuer)
        let keys = try FountainAuthMemoryKeyStore(keyID: "restart-key")
        let firstStore = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let firstServer = try FountainAuthAuthorizationServer(
            metadata: metadata,
            keyStore: keys,
            stateStore: firstStore,
            tokenLifetime: 120)
        try await firstServer.register(FountainAuthClientRegistration(
            clientID: "reframe-native",
            redirectURIs: [redirect]))

        let verifier = "restart-verifier-value-123456789012345678901234"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "reframe-native",
            redirectURI: redirect,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-restart",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource,
            correlationID: "corr-restart",
            expiresAt: Date().addingTimeInterval(120))
        let code = try await firstServer.begin(
            request,
            subjectReference: "subject:writer",
            authenticationMechanism: "fixture-authentication-adapter",
            decision: .approved)

        let afterIssue = try String(contentsOf: stateURL, encoding: .utf8)
        XCTAssertFalse(afterIssue.contains(code.value))
        XCTAssertTrue(afterIssue.contains("reframe-native"))

        let secondStore = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let secondServer = try FountainAuthAuthorizationServer(
            metadata: metadata,
            keyStore: keys,
            stateStore: secondStore,
            tokenLifetime: 120)
        let token = try await secondServer.redeem(
            code: code.value,
            clientID: request.clientID,
            redirectURI: request.redirectURI,
            verifier: verifier,
            resource: resource)

        let afterRedeem = try String(contentsOf: stateURL, encoding: .utf8)
        XCTAssertFalse(afterRedeem.contains(code.value))
        XCTAssertFalse(afterRedeem.contains(token.value))

        let thirdStore = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let thirdServer = try FountainAuthAuthorizationServer(
            metadata: metadata,
            keyStore: keys,
            stateStore: thirdStore,
            tokenLifetime: 120)
        do {
            _ = try await thirdServer.redeem(
                code: code.value,
                clientID: request.clientID,
                redirectURI: request.redirectURI,
                verifier: verifier,
                resource: resource)
            XCTFail("consumed authorization code must remain consumed after restart")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .unknownCode)
        }

        try await thirdServer.revoke(token)
        let fourthStore = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let fourthServer = try FountainAuthAuthorizationServer(
            metadata: metadata,
            keyStore: keys,
            stateStore: fourthStore,
            tokenLifetime: 120)
        do {
            _ = try await fourthServer.validate(
                token,
                resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("revocation must survive restart")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }

        let finalSnapshot = try String(contentsOf: stateURL, encoding: .utf8)
        XCTAssertFalse(finalSnapshot.contains(token.value))
        XCTAssertFalse(finalSnapshot.contains(code.value))
    }

    func testManageClientAccessScenarioHasBoundedIdentityAndTerminalProof() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("Scenarios/manage-client-access.json"))
        let scenario = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(scenario["id"] as? String, "fcis-manage-client-access")
        XCTAssertEqual(scenario["instrument"] as? String, FountainAuthInstrument.identity)
        XCTAssertEqual(scenario["targetKind"] as? String, "system-boundary")
        XCTAssertEqual((scenario["actions"] as? [[String: Any]])?.count, 6)
        XCTAssertEqual((scenario["terminalPredicates"] as? [String])?.count, 7)
        XCTAssertTrue((scenario["claimBoundary"] as? String)?.contains("no live ChatGPT revoke") == true)
        XCTAssertEqual(FountainAuthInstrument.revokeTopic, "fountaincoach/authorization.revoke")
        XCTAssertEqual(FountainAuthInstrument.revokeResultTopic, "fountaincoach/authorization.revoke.result")
    }

    func testManageClientAccessEventRevokeIsScopedDurableIdempotentAndReauthorizable() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-manage-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("authority-state.json")
        let issuer = URL(string: "https://auth.manage.example")!
        let resource = URL(string: "https://mcp.manage.example/mcp")!
        let redirect = URL(string: "http://isolated-client.localhost/callback")!
        let clientID = "isolated-scenario-client"
        let metadata = try durableMetadata(issuer: issuer)
        let keys = try FountainAuthMemoryKeyStore(keyID: "manage-fixture-key")

        let firstState = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let firstServer = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys, stateStore: firstState, tokenLifetime: 120)
        try await firstServer.register(FountainAuthClientRegistration(
            clientID: clientID, redirectURIs: [redirect]))
        let verifier = "manage-scenario-verifier-123456789012345678901234"
        func makeRequest(state: String) throws -> FountainAuthAuthorizationRequest {
            try FountainAuthAuthorizationRequest(
                clientID: clientID, redirectURI: redirect,
                scope: [FountainAuthHostDescribeAdmission.capability],
                state: state,
                codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
                resource: resource, correlationID: "manage-client-\(state)",
                expiresAt: Date().addingTimeInterval(120))
        }
        let firstRequest = try makeRequest(state: "before-revoke")
        let firstCode = try await firstServer.begin(
            firstRequest, subjectReference: "owner:scenario",
            authenticationMechanism: "isolated-consent-fixture", decision: .approved)
        let oldToken = try await firstServer.redeem(
            code: firstCode.value, clientID: clientID, redirectURI: redirect,
            verifier: verifier, resource: resource)
        let accepted = try await firstServer.validate(
            oldToken, resource: resource,
            requiredScope: FountainAuthHostDescribeAdmission.capability)
        XCTAssertEqual(accepted.clientID, clientID)
        XCTAssertEqual(accepted.authorizationEventID, firstCode.evidence.authorizationEventID)

        // An owner adapter supplies an exact client/resource, not an unbounded ID.
        for (wrongClient, wrongResource) in [
            ("other-client", resource),
            (clientID, URL(string: "https://other-resource.example/mcp")!)
        ] {
            do {
                _ = try await firstServer.revokeAuthorizationEvent(
                    firstCode.evidence.authorizationEventID,
                    clientID: wrongClient, resource: wrongResource)
                XCTFail("wrong client/resource must not revoke a grant")
            } catch {
                XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
            }
        }
        do {
            _ = try await firstServer.revokeAuthorizationEvent(
                "unknown-event", clientID: clientID, resource: resource)
            XCTFail("unknown event must not be revoked")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }
        let firstOutcome = try await firstServer.revokeAuthorizationEvent(
            firstCode.evidence.authorizationEventID,
            clientID: clientID, resource: resource)
        XCTAssertEqual(firstOutcome, .revoked)
        let repeated = try await firstServer.revokeAuthorizationEvent(
            firstCode.evidence.authorizationEventID,
            clientID: clientID, resource: resource)
        XCTAssertEqual(repeated, .alreadyRevoked)
        do {
            _ = try await firstServer.validate(
                oldToken, resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("revoked authorization event must invalidate a previously issued access token")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }

        let otherIssuer = URL(string: "https://unrelated-issuer.example")!
        let otherServer = try FountainAuthAuthorizationServer(
            metadata: durableMetadata(issuer: otherIssuer), keyStore: keys,
            stateStore: try FountainAuthFileAuthorityStateStore(fileURL: stateURL))
        do {
            _ = try await otherServer.revokeAuthorizationEvent(
                firstCode.evidence.authorizationEventID,
                clientID: clientID, resource: resource)
            XCTFail("a different issuer must refuse a matching event ID")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }

        let restarted = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: try FountainAuthFileAuthorityStateStore(fileURL: stateURL),
            tokenLifetime: 120)
        do {
            _ = try await restarted.validate(
                oldToken, resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("revocation must survive restart")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }
        let replayAfterRestart = try await restarted.revokeAuthorizationEvent(
            firstCode.evidence.authorizationEventID,
            clientID: clientID, resource: resource)
        XCTAssertEqual(replayAfterRestart, .alreadyRevoked)

        let secondRequest = try makeRequest(state: "after-new-consent")
        let secondCode = try await restarted.begin(
            secondRequest, subjectReference: "owner:scenario",
            authenticationMechanism: "isolated-consent-fixture", decision: .approved)
        XCTAssertNotEqual(firstCode.evidence.authorizationEventID,
                          secondCode.evidence.authorizationEventID)
        let newToken = try await restarted.redeem(
            code: secondCode.value, clientID: clientID, redirectURI: redirect,
            verifier: verifier, resource: resource)
        let restored = try await restarted.validate(
            newToken, resource: resource,
            requiredScope: FountainAuthHostDescribeAdmission.capability)
        XCTAssertEqual(restored.authorizationEventID, secondCode.evidence.authorizationEventID)

        let file = try String(contentsOf: stateURL, encoding: .utf8)
        XCTAssertFalse(file.contains(oldToken.value))
        XCTAssertFalse(file.contains(newToken.value))
        XCTAssertFalse(file.contains(firstCode.value))
        XCTAssertFalse(file.contains(secondCode.value))
        XCTAssertTrue(file.contains("issuedAuthorizationEvents"))
        XCTAssertTrue(file.contains(firstCode.evidence.authorizationEventID))
    }

    func testProtectedResourceValidatorReadsLiveRevocationAcrossRestartAndFailsClosed() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-resource-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("authority-state.json")
        let issuer = URL(string: "https://auth.resource.example")!
        let resource = URL(string: "https://mcp.resource.example/mcp")!
        let redirect = URL(string: "http://isolated-resource.localhost/callback")!
        let clientID = "isolated-resource-client"
        let keys = try FountainAuthMemoryKeyStore(keyID: "isolated-public-verification")
        let state = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let server = try FountainAuthAuthorizationServer(
            metadata: durableMetadata(issuer: issuer),
            keyStore: keys, stateStore: state, tokenLifetime: 120)
        try await server.register(FountainAuthClientRegistration(
            clientID: clientID, redirectURIs: [redirect]))
        let verifier = "protected-resource-verifier-123456789012345678901234"
        let request = try FountainAuthAuthorizationRequest(
            clientID: clientID, redirectURI: redirect,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "isolated-resource-consent",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource, correlationID: "resource-revoke-fixture",
            expiresAt: Date().addingTimeInterval(120))
        let code = try await server.begin(
            request, subjectReference: "owner:isolated",
            authenticationMechanism: "fixture-consent", decision: .approved)
        let access = try await server.redeem(
            code: code.value, clientID: clientID, redirectURI: redirect,
            verifier: verifier, resource: resource)
        let liveReader = try FountainAuthFileRevocationReader(fileURL: stateURL)
        let publicResourceValidator = try FountainAuthProtectedResourceValidator(
            issuer: issuer, keyStore: keys,
            isRevoked: { tokenID, eventID, exactIssuer, exactClient, exactResource in
                try liveReader.isRevoked(
                    tokenID: tokenID, authorizationEventID: eventID,
                    issuer: exactIssuer, clientID: exactClient, resource: exactResource)
            })
        let admitted = try await publicResourceValidator.validateBearer(
            access.value, resource: resource,
            requiredScope: FountainAuthHostDescribeAdmission.capability)
        XCTAssertEqual(admitted.clientID, clientID)
        XCTAssertEqual(admitted.authorizationEventID, code.evidence.authorizationEventID)

        let outcome = try await server.revokeAuthorizationEvent(
            code.evidence.authorizationEventID, clientID: clientID, resource: resource)
        XCTAssertEqual(outcome, .revoked)
        do {
            _ = try await publicResourceValidator.validateBearer(
                access.value, resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("independent resource must reject a revoked authorization")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }

        let validatorAfterRestart = try FountainAuthProtectedResourceValidator(
            issuer: issuer, keyStore: keys,
            isRevoked: { tokenID, eventID, exactIssuer, exactClient, exactResource in
                try FountainAuthFileRevocationReader(fileURL: stateURL).isRevoked(
                    tokenID: tokenID, authorizationEventID: eventID,
                    issuer: exactIssuer, clientID: exactClient, resource: exactResource)
            })
        do {
            _ = try await validatorAfterRestart.validateBearer(
                access.value, resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("resource must still deny after durable state reload")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }
        enum RevocationReaderDown: Error { case offline }
        let unavailable = try FountainAuthProtectedResourceValidator(
            issuer: issuer, keyStore: keys,
            isRevoked: { _, _, _, _, _ in throw RevocationReaderDown.offline })
        do {
            _ = try await unavailable.validateBearer(
                access.value, resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("missing current revocation state must fail closed")
        } catch {
            XCTAssertTrue(error is RevocationReaderDown)
        }
        do {
            _ = try await validatorAfterRestart.validateBearer(
                access.value, resource: URL(string: "https://wrong-resource.example/mcp")!,
                requiredScope: FountainAuthHostDescribeAdmission.capability)
            XCTFail("cross-resource token must fail closed")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidToken)
        }
    }

    func testFileRevocationReaderSeesIssuerWritesAfterConstructionAndDeniesUnavailableState() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-reader-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("authority.json")
        let issuer = URL(string: "https://auth.fresh-reader.example")!
        let foreignIssuer = URL(string: "https://auth.foreign-reader.example")!
        let resource = URL(string: "https://mcp.fresh-reader.example/mcp")!
        let wrongResource = URL(string: "https://other.fresh-reader.example/mcp")!
        let clientID = "scenario-isolated-client"
        let eventID = "scenario-authorization-event"
        let tokenID = "scenario-short-lived-token"
        let writer = try FountainAuthFileAuthorityStateStore(fileURL: fileURL)
        let reader = try FountainAuthFileRevocationReader(fileURL: fileURL)

        // Missing state cannot silently become an allow.
        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: clientID, resource: resource))

        try await writer.recordIssuedAuthorizationEvent(
            FountainAuthIssuedAuthorizationEvent(
                authorizationEventID: eventID, clientID: clientID, resource: resource),
            issuer: issuer)
        XCTAssertFalse(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: clientID, resource: resource))

        // The validator is a separate long-running consumer. It must read the
        // issuer's NEW bytes rather than a snapshot captured when constructed.
        let issuerWriter = try FountainAuthFileAuthorityStateStore(fileURL: fileURL)
        let result = try await issuerWriter.revokeAuthorizationEvent(
            eventID, issuer: issuer, clientID: clientID, resource: resource)
        XCTAssertEqual(result, .revoked)
        XCTAssertTrue(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: clientID, resource: resource))

        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: "other-client", resource: resource))
        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: clientID, resource: wrongResource))
        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: foreignIssuer, clientID: clientID, resource: resource))
        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: "unknown-event",
            issuer: issuer, clientID: clientID, resource: resource))

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: fileURL.path)
        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: clientID, resource: resource))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        try Data("not-json".utf8).write(to: fileURL, options: .atomic)
        XCTAssertThrowsError(try reader.isRevoked(
            tokenID: tokenID, authorizationEventID: eventID,
            issuer: issuer, clientID: clientID, resource: resource))
    }

    func testLegacyRefreshCompatibilityPreflightPreservesExistingDigestFormatAndRefusesMismatch() throws {
        let client = try FountainAuthClientRegistration(
            clientID: "isolated-legacy", redirectURIs: [
                URL(string: "http://isolated-legacy.localhost/callback")!])
        let clientBytes = try JSONEncoder().encode([client])
        let resource = URL(string: "https://mcp.legacy.example/mcp")!
        let issuedAt = Date(timeIntervalSinceReferenceDate: 700_000_000)
        let currentDigest = String(repeating: "a", count: 64)
        let olderDigest = String(repeating: "b", count: 64)
        var family: [String: Any] = [
            "familyID": "isolated-legacy-family",
            "clientID": client.clientID,
            "resource": resource.absoluteString,
            "subjectReference": "owner:isolated",
            "grantedScope": ["host.describe"],
            "authorizedAt": issuedAt.timeIntervalSinceReferenceDate,
            "expiresAt": issuedAt.addingTimeInterval(600).timeIntervalSinceReferenceDate,
            "authorizationEventID": "isolated-authorization-event",
            "authenticationMechanism": "http-basic-owner",
            "correlationID": "isolated-correlation",
            "currentDigest": currentDigest,
            "consumedDigests": [olderDigest],
            "revoked": false
        ]
        func inspect(_ family: [String: Any]) throws
            -> FountainAuthLegacyRefreshPreflight.Receipt {
            try FountainAuthLegacyRefreshPreflight.inspect(
                clientsJSON: clientBytes,
                refreshFamiliesJSON: JSONSerialization.data(withJSONObject: [family]),
                permittedResource: resource)
        }
        let receipt = try inspect(family)
        XCTAssertEqual(receipt.clients, 1)
        XCTAssertEqual(receipt.refreshFamilies, 1)
        XCTAssertEqual(receipt.revokedFamilies, 0)
        XCTAssertEqual(receipt.authorizationEvents, 1)

        family["currentDigest"] = "plaintext-refresh"
        XCTAssertThrowsError(try inspect(family))
        family["currentDigest"] = currentDigest
        family["clientID"] = "not-registered"
        XCTAssertThrowsError(try inspect(family))
        family["clientID"] = client.clientID
        family["resource"] = "https://other-resource.example/mcp"
        XCTAssertThrowsError(try inspect(family))
        family["resource"] = resource.absoluteString
        family["consumedDigests"] = [olderDigest, olderDigest]
        XCTAssertThrowsError(try inspect(family))
        family["consumedDigests"] = [olderDigest]
        family["revoked"] = true
        XCTAssertEqual(try inspect(family).revokedFamilies, 1)
    }

    func testRefreshRotationReplayRevokesAccessAndNewConsentRestoresIt() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-refresh-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("authority.json")
        let issuer = URL(string: "https://auth.refresh.example")!
        let resource = URL(string: "https://mcp.refresh.example/mcp")!
        let redirect = URL(string: "http://refresh.localhost/callback")!
        let metadata = try FountainAuthServerMetadata(
            issuer: issuer,
            authorizationEndpoint: issuer.appendingPathComponent("oauth/authorize"),
            tokenEndpoint: issuer.appendingPathComponent("oauth/token"),
            jwksURI: issuer.appendingPathComponent(".well-known/jwks.json"),
            scopesSupported: ["host.describe"],
            grantTypesSupported: ["authorization_code", "refresh_token"])
        let keys = try FountainAuthMemoryKeyStore(keyID: "refresh-key")
        let first = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: FountainAuthFileAuthorityStateStore(fileURL: path))
        try await first.register(FountainAuthClientRegistration(
            clientID: "isolated-refresh", redirectURIs: [redirect]))
        let verifier = "isolated-refresh-verifier-123456789012345678901234"
        func request(_ state: String) throws -> FountainAuthAuthorizationRequest {
            try FountainAuthAuthorizationRequest(
                clientID: "isolated-refresh", redirectURI: redirect,
                scope: ["host.describe"], state: state,
                codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
                resource: resource, correlationID: "refresh-" + state,
                expiresAt: Date().addingTimeInterval(120))
        }
        let firstCode = try await first.begin(
            request("first"), subjectReference: "owner:isolated",
            authenticationMechanism: "fixture-consent", decision: .approved)
        let pair = try await first.redeemWithRefresh(
            code: firstCode.value, clientID: "isolated-refresh",
            redirectURI: redirect, verifier: verifier, resource: resource)
        _ = try await first.validate(pair.access, resource: resource,
                                     requiredScope: "host.describe")
        let rotated = try await first.rotateRefresh(
            token: pair.refreshToken, clientID: "isolated-refresh", resource: resource)
        XCTAssertNotEqual(pair.refreshToken, rotated.refreshToken)
        XCTAssertEqual(pair.access.evidence.authorizationEventID,
                       rotated.access.evidence.authorizationEventID)

        do {
            _ = try await first.rotateRefresh(
                token: rotated.refreshToken, clientID: "isolated-refresh",
                resource: URL(string: "https://wrong-resource.example/mcp")!)
            XCTFail("cross-resource rotation must refuse")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }
        // A new issuer process on the same frozen file sees the correct head.
        let restarted = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: FountainAuthFileAuthorityStateStore(fileURL: path))
        let third = try await restarted.rotateRefresh(
            token: rotated.refreshToken, clientID: "isolated-refresh", resource: resource)
        _ = try await restarted.validate(
            third.access, resource: resource, requiredScope: "host.describe")
        do {
            _ = try await restarted.rotateRefresh(
                token: pair.refreshToken, clientID: "isolated-refresh", resource: resource)
            XCTFail("spent refresh replay must revoke its entire family")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }
        let reader = try FountainAuthFileRevocationReader(fileURL: path)
        let separateResource = try FountainAuthProtectedResourceValidator(
            issuer: issuer, keyStore: keys,
            isRevoked: { tokenID, eventID, exactIssuer, client, boundResource in
                try reader.isRevoked(
                    tokenID: tokenID, authorizationEventID: eventID,
                    issuer: exactIssuer, clientID: client, resource: boundResource)
            })
        do {
            _ = try await separateResource.validateBearer(
                third.access.value, resource: resource, requiredScope: "host.describe")
            XCTFail("old access must be denied at a distinct protected resource")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }
        do {
            _ = try await restarted.rotateRefresh(
                token: third.refreshToken, clientID: "isolated-refresh", resource: resource)
            XCTFail("family remains revoked after replay")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }

        let finalServer = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: FountainAuthFileAuthorityStateStore(fileURL: path))
        let secondCode = try await finalServer.begin(
            request("new-consent"), subjectReference: "owner:isolated",
            authenticationMechanism: "fixture-consent", decision: .approved)
        let fresh = try await finalServer.redeemWithRefresh(
            code: secondCode.value, clientID: "isolated-refresh",
            redirectURI: redirect, verifier: verifier, resource: resource)
        XCTAssertNotEqual(fresh.access.evidence.authorizationEventID,
                          third.access.evidence.authorizationEventID)
        _ = try await separateResource.validateBearer(
            fresh.access.value, resource: resource, requiredScope: "host.describe")
        let persisted = try String(contentsOf: path, encoding: .utf8)
        XCTAssertFalse(persisted.contains(pair.refreshToken))
        XCTAssertFalse(persisted.contains(rotated.refreshToken))
        XCTAssertFalse(persisted.contains(third.refreshToken))
        XCTAssertFalse(persisted.contains(fresh.refreshToken))
        XCTAssertFalse(persisted.contains(pair.access.value))
        XCTAssertTrue(persisted.contains("refreshFamilies"))
    }

    func testLegacyFrozenSnapshotImportPreservesRefreshAndRefusesSecondWriter() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-import-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("authority.json")
        let issuer = URL(string: "https://auth.migration.example")!
        let resource = URL(string: "https://mcp.migration.example/mcp")!
        let redirect = URL(string: "http://legacy-isolated.localhost/callback")!
        let metadata = try FountainAuthServerMetadata(
            issuer: issuer,
            authorizationEndpoint: issuer.appendingPathComponent("oauth/authorize"),
            tokenEndpoint: issuer.appendingPathComponent("oauth/token"),
            jwksURI: issuer.appendingPathComponent(".well-known/jwks.json"),
            scopesSupported: ["host.describe"],
            grantTypesSupported: ["authorization_code", "refresh_token"])
        let keys = try FountainAuthMemoryKeyStore(keyID: "legacy-preserved-key")
        let client = try FountainAuthClientRegistration(
            clientID: "isolated-legacy", redirectURIs: [redirect])
        let legacyRefresh = String(repeating: "A", count: 64)
        let digest = SHA256.hash(data: Data(legacyRefresh.utf8))
            .map { String(format: "%02x", $0) }.joined()
        let family = FountainAuthRefreshFamily(
            familyID: "legacy-family-1", clientID: client.clientID,
            resource: resource, subjectReference: "owner:isolated",
            grantedScope: ["host.describe"],
            authorizedAt: Date().addingTimeInterval(-60),
            expiresAt: Date().addingTimeInterval(7200),
            authorizationEventID: "legacy-event-1",
            authenticationMechanism: "fixture-basic-owner",
            correlationID: "legacy-migration-test",
            currentDigest: digest, consumedDigests: [])
        let clientsJSON = try JSONEncoder().encode([client])
        let familiesJSON = try JSONEncoder().encode([family])
        let server = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: FountainAuthFileAuthorityStateStore(fileURL: path))
        let receipt = try await server.importLegacy(
            clientsJSON: clientsJSON, refreshFamiliesJSON: familiesJSON,
            permittedResource: resource)
        XCTAssertEqual(receipt.clients, 1)
        XCTAssertEqual(receipt.refreshFamilies, 1)
        XCTAssertEqual(receipt.authorizationEvents, 1)
        let snapshotBeforeDuplicate = try Data(contentsOf: path)
        do {
            _ = try await server.importLegacy(
                clientsJSON: clientsJSON, refreshFamiliesJSON: familiesJSON,
                permittedResource: resource)
            XCTFail("second writer/import must refuse even identical legacy records")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorityStateConflict)
        }
        XCTAssertEqual(try Data(contentsOf: path), snapshotBeforeDuplicate)
        let preservedFamilies = try JSONDecoder().decode(
            [FountainAuthRefreshFamily].self, from: familiesJSON)
        XCTAssertEqual(preservedFamilies, [family])

        let restarted = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: FountainAuthFileAuthorityStateStore(fileURL: path))
        let rotated = try await restarted.rotateRefresh(
            token: legacyRefresh, clientID: "isolated-legacy", resource: resource)
        XCTAssertEqual(rotated.access.evidence.authorizationEventID, family.authorizationEventID)
        let admitted = try await restarted.validate(
            rotated.access, resource: resource, requiredScope: "host.describe")
        XCTAssertEqual(admitted.clientID, client.clientID)

        do {
            _ = try await restarted.rotateRefresh(
                token: legacyRefresh, clientID: "isolated-legacy", resource: resource)
            XCTFail("replayed legacy token must revoke the imported family")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }
        let finalServer = try FountainAuthAuthorizationServer(
            metadata: metadata, keyStore: keys,
            stateStore: FountainAuthFileAuthorityStateStore(fileURL: path))
        do {
            _ = try await finalServer.validate(
                rotated.access, resource: resource, requiredScope: "host.describe")
            XCTFail("revocation must be durable")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .tokenRevoked)
        }
        let saved = try String(contentsOf: path, encoding: .utf8)
        XCTAssertTrue(saved.contains(digest))
        XCTAssertFalse(saved.contains(legacyRefresh))
        XCTAssertFalse(saved.contains(rotated.refreshToken))
    }

    func testLegacyAuthoritySnapshotDecodesWithoutIssuedEventIndex() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-legacy-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("state.json")
        let issuer = URL(string: "https://legacy.example")!
        let state = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        try await state.register(client: FountainAuthClientRegistration(
            clientID: "legacy-native", redirectURIs: [
                URL(string: "http://legacy.localhost/callback")!]), issuer: issuer)
        var legacy = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: stateURL)) as? [String: Any])
        legacy.removeValue(forKey: "issuedAuthorizationEvents")
        try JSONSerialization.data(withJSONObject: legacy).write(to: stateURL, options: .atomic)
        let reopened = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let existing = try await reopened.client(issuer: issuer, clientID: "legacy-native")
        XCTAssertEqual(existing?.clientID, "legacy-native")
        let legacyRevoked = try await reopened.isAuthorizationEventRevoked(
            "unknown-legacy-event", issuer: issuer)
        XCTAssertFalse(legacyRevoked)
    }

    func testDurableDomainRegistrySurvivesRuntimeRestartAndStillFailsClosed() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-domain-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("authority-state.json")
        let issuerA = URL(string: "https://auth.a.restart.example")!
        let issuerB = URL(string: "https://auth.b.restart.example")!
        let store = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let serverA = try FountainAuthAuthorizationServer(
            metadata: durableMetadata(issuer: issuerA),
            keyStore: FountainAuthMemoryKeyStore(),
            stateStore: store)
        let serverB = try FountainAuthAuthorizationServer(
            metadata: durableMetadata(issuer: issuerB),
            keyStore: FountainAuthMemoryKeyStore(),
            stateStore: store)
        let runtime = FountainAuthDomainRuntime(stateStore: store)
        try await runtime.admit(issuer: issuerA, authority: serverA)
        try await runtime.admit(issuer: issuerB, authority: serverB)

        let restartedStore = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let restartedRuntime = FountainAuthDomainRuntime(stateStore: restartedStore)
        let restartedIssuers = try await restartedRuntime.admittedIssuers()
        XCTAssertEqual(restartedIssuers, [
            "https://auth.a.restart.example",
            "https://auth.b.restart.example"
        ])

        let restartedServerA = try FountainAuthAuthorizationServer(
            metadata: durableMetadata(issuer: issuerA),
            keyStore: FountainAuthMemoryKeyStore(),
            stateStore: restartedStore)
        try await restartedRuntime.bind(issuer: issuerA, authority: restartedServerA)
        let rebound = try await restartedRuntime.authority(for: issuerA)
        let reboundMetadata = await rebound.metadata
        XCTAssertEqual(reboundMetadata.issuer, issuerA)

        do {
            _ = try await restartedRuntime.authority(
                for: URL(string: "https://auth.unknown.restart.example")!)
            XCTFail("unknown issuer must never fall back after restart")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidIssuer)
        }
    }

    func testDurableAuthorizationCodeConsumptionIsAtomicAcrossConcurrentRedeemers() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-race-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("authority-state.json")
        let issuer = URL(string: "https://auth.race.example")!
        let resource = URL(string: "https://mcp.race.example")!
        let redirect = URL(string: "http://reframe.localhost/callback")!
        let store = try FountainAuthFileAuthorityStateStore(fileURL: stateURL)
        let keys = try FountainAuthMemoryKeyStore(keyID: "race-key")
        let server = try FountainAuthAuthorizationServer(
            metadata: durableMetadata(issuer: issuer),
            keyStore: keys,
            stateStore: store)
        try await server.register(FountainAuthClientRegistration(
            clientID: "reframe-native", redirectURIs: [redirect]))

        let verifier = "race-verifier-value-123456789012345678901234567"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "reframe-native",
            redirectURI: redirect,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-race",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource,
            correlationID: "corr-race",
            expiresAt: Date().addingTimeInterval(120))
        let code = try await server.begin(
            request,
            subjectReference: "subject:writer",
            authenticationMechanism: "fixture-authentication-adapter",
            decision: .approved)

        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0..<2 {
                group.addTask {
                    do {
                        _ = try await server.redeem(
                            code: code.value,
                            clientID: request.clientID,
                            redirectURI: request.redirectURI,
                            verifier: verifier,
                            resource: resource)
                        return true
                    } catch {
                        return false
                    }
                }
            }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
        XCTAssertEqual(results.filter { !$0 }.count, 1)
    }

}


extension FountainAuthKitTests {
    func testSigningKeyLifecycleSurvivesRestartRetiresAndRecoversAfterCompromise() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FountainAuthKit-keys-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let lifecycleURL = directory.appendingPathComponent("key-lifecycle.json")
        let lifecycleStore = try FountainAuthFileSigningKeyLifecycleStore(fileURL: lifecycleURL)
        let secretStore = TestSecretStore()

        let firstPrivate = Curve25519.Signing.PrivateKey()
        let first = try FountainAuthSecretKeyReference(keyID: "key-1", account: "account-1")
        try secretStore.storeSecret(firstPrivate.rawRepresentation, for: first.account)

        let t0 = Date()
        let keys = try await FountainAuthSecretStoreKeyStore(
            store: secretStore,
            initialActive: first,
            lifecycleStore: lifecycleStore,
            now: t0)

        let issuer = URL(string: "https://auth.keys.example")!
        let resource = URL(string: "https://mcp.keys.example")!
        let redirect = URL(string: "http://reframe.localhost/callback")!
        let metadata = try durableMetadata(issuer: issuer)
        let state = FountainAuthMemoryAuthorityStateStore()
        let server = try FountainAuthAuthorizationServer(
            metadata: metadata,
            keyStore: keys,
            stateStore: state,
            tokenLifetime: 600)
        try await server.register(FountainAuthClientRegistration(
            clientID: "reframe-native", redirectURIs: [redirect]))

        let verifier1 = "key-lifecycle-verifier-123456789012345678901234567"
        let request1 = try FountainAuthAuthorizationRequest(
            clientID: "reframe-native",
            redirectURI: redirect,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-key-1",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier1),
            resource: resource,
            correlationID: "corr-key-1",
            expiresAt: t0.addingTimeInterval(120))
        let code1 = try await server.begin(
            request1,
            subjectReference: "subject:writer",
            authenticationMechanism: "fixture-authentication-adapter",
            decision: .approved,
            now: t0)
        let token1 = try await server.redeem(
            code: code1.value,
            clientID: request1.clientID,
            redirectURI: request1.redirectURI,
            verifier: verifier1,
            resource: resource,
            now: t0)

        let second = try FountainAuthSecretKeyReference(keyID: "key-2", account: "account-2")
        let overlapEnd = t0.addingTimeInterval(60)
        try await keys.rotate(to: second, overlapUntil: overlapEnd, now: t0.addingTimeInterval(1))

        _ = try await server.validate(
            token1,
            resource: resource,
            requiredScope: FountainAuthHostDescribeAdmission.capability,
            now: t0.addingTimeInterval(30))

        let lifecycleText = try String(contentsOf: lifecycleURL, encoding: .utf8)
        XCTAssertFalse(lifecycleText.contains(firstPrivate.rawRepresentation.base64EncodedString()))
        XCTAssertTrue(lifecycleText.contains("verificationOverlap"))
        XCTAssertTrue(lifecycleText.contains("key-2"))

        let restartedLifecycle = try FountainAuthFileSigningKeyLifecycleStore(fileURL: lifecycleURL)
        let restartedKeys = try await FountainAuthSecretStoreKeyStore(
            store: secretStore,
            initialActive: second,
            lifecycleStore: restartedLifecycle,
            now: t0.addingTimeInterval(30))
        let restartedServer = try FountainAuthAuthorizationServer(
            metadata: metadata,
            keyStore: restartedKeys,
            stateStore: state,
            tokenLifetime: 600)

        _ = try await restartedServer.validate(
            token1,
            resource: resource,
            requiredScope: FountainAuthHostDescribeAdmission.capability,
            now: t0.addingTimeInterval(30))

        try await restartedKeys.retireExpired(now: overlapEnd)
        do {
            _ = try await restartedServer.validate(
                token1,
                resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability,
                now: overlapEnd)
            XCTFail("retired key must not verify after overlap deadline")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidToken)
        }

        let verifier2 = "key-compromise-verifier-12345678901234567890123456"
        let request2 = try FountainAuthAuthorizationRequest(
            clientID: "reframe-native",
            redirectURI: redirect,
            scope: [FountainAuthHostDescribeAdmission.capability],
            state: "state-key-2",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier2),
            resource: resource,
            correlationID: "corr-key-2",
            expiresAt: t0.addingTimeInterval(180))
        let code2 = try await server.begin(
            request2,
            subjectReference: "subject:writer",
            authenticationMechanism: "fixture-authentication-adapter",
            decision: .approved,
            now: t0.addingTimeInterval(70))
        let token2 = try await server.redeem(
            code: code2.value,
            clientID: request2.clientID,
            redirectURI: request2.redirectURI,
            verifier: verifier2,
            resource: resource,
            now: t0.addingTimeInterval(70))

        try await restartedKeys.markCompromised(keyID: second.keyID, now: t0.addingTimeInterval(80))
        XCTAssertNil(try secretStore.retrieveSecret(for: second.account))
        do {
            _ = try await restartedServer.validate(
                token2,
                resource: resource,
                requiredScope: FountainAuthHostDescribeAdmission.capability,
                now: t0.addingTimeInterval(81))
            XCTFail("compromised key must stop verifying immediately")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .invalidToken)
        }
        do {
            _ = try await restartedKeys.activeSigningKey()
            XCTFail("compromised active key must remove signing authority")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .keyUnavailable)
        }

        let postCompromiseLifecycle = try FountainAuthFileSigningKeyLifecycleStore(fileURL: lifecycleURL)
        let postCompromiseKeys = try await FountainAuthSecretStoreKeyStore(
            store: secretStore,
            initialActive: second,
            lifecycleStore: postCompromiseLifecycle,
            now: t0.addingTimeInterval(85))
        do {
            _ = try await postCompromiseKeys.activeSigningKey()
            XCTFail("restart after compromise must remain fail-closed until recovery")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .keyUnavailable)
        }

        let recovered = try FountainAuthSecretKeyReference(keyID: "key-3", account: "account-3")
        try await postCompromiseKeys.recover(with: recovered, now: t0.addingTimeInterval(90))
        let recoveredActive = try await postCompromiseKeys.activeSigningKey()
        XCTAssertEqual(recoveredActive.keyID, recovered.keyID)
        XCTAssertNotNil(try secretStore.retrieveSecret(for: recovered.account))

        let finalRecords = await postCompromiseKeys.lifecycle()
        XCTAssertEqual(finalRecords.first(where: { $0.reference.keyID == first.keyID })?.state, .retired)
        XCTAssertEqual(finalRecords.first(where: { $0.reference.keyID == second.keyID })?.state, .compromised)
        XCTAssertEqual(finalRecords.first(where: { $0.reference.keyID == recovered.keyID })?.state, .active)
    }
}

extension FountainAuthKitTests {
    func testHumanDenialCannotBecomeAuthorization() async throws {
        let (server, _, _, resource) = try await server()
        let verifier = "denial-verifier-value-123456789012345678901234567"
        let request = try FountainAuthAuthorizationRequest(
            clientID: "native-client",
            redirectURI: URL(string: "http://app.localhost/callback")!,
            scope: ["estate.inspect"],
            state: "state-denied",
            codeChallenge: FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier),
            resource: resource,
            correlationID: "corr-denied",
            expiresAt: Date().addingTimeInterval(60))
        do {
            _ = try await server.begin(
                request,
                subjectReference: "subject:owner-1",
                authenticationMechanism: "fixture-authentication-adapter",
                decision: .denied)
            XCTFail("authentication must not become authorization after human denial")
        } catch {
            XCTAssertEqual(error as? FountainAuthError, .authorizationDenied)
        }
    }
}
