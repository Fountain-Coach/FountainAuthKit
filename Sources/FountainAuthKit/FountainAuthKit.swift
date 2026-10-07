@preconcurrency import Crypto
import Foundation
import SecretStore

/// Reusable Fountain-owned authorization authority. Upstream authentication,
/// host mediation, SecretStore custody, and protected resources remain
/// separate adapters.
public enum FountainAuthInstrument {
    public static let identity = "fountaincoach.authorization@0.1.0"
    public static let version = "0.1.0"
    public static let discoverTopic = "fountaincoach/authorization.discover"
    public static let discoverResultTopic = "fountaincoach/authorization.discover.result"
    public static let beginTopic = "fountaincoach/authorization.begin"
    public static let beginResultTopic = "fountaincoach/authorization.begin.result"
    public static let revokeTopic = "fountaincoach/authorization.revoke"
    public static let revokeResultTopic = "fountaincoach/authorization.revoke.result"
    public static let protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
    public static let authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
}

public enum FountainAuthError: Error, Equatable, Sendable {
    case invalidIssuer
    case invalidEndpoint
    case invalidClient
    case invalidRedirect
    case invalidRequest
    case invalidPKCE
    case humanDecisionRequired
    case authorizationDenied
    case unknownCode
    case codeExpired
    case codeReplayed
    case resourceMismatch
    case scopeMissing(String)
    case invalidToken
    case tokenExpired
    case tokenRevoked
    case issuerMismatch
    case clientMismatch
    case keyUnavailable
    case invalidSecretReference
    case invalidStoredKey
    case secretStoreUnavailable
    case keyAlreadyExists
    case evidenceConflict
    case authorityStateConflict
    case invalidKeyLifecycle
    case keyRetired
    case keyCompromised
}

public struct FountainAuthServerMetadata: Codable, Equatable, Sendable {
    public let issuer: URL
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    public let jwksURI: URL
    public let scopesSupported: [String]
    public let responseTypesSupported: [String]
    public let grantTypesSupported: [String]
    public let codeChallengeMethodsSupported: [String]

    public init(issuer: URL, authorizationEndpoint: URL, tokenEndpoint: URL, jwksURI: URL,
                scopesSupported: [String], responseTypesSupported: [String] = ["code"],
                grantTypesSupported: [String] = ["authorization_code"],
                codeChallengeMethodsSupported: [String] = ["S256"]) throws {
        guard Self.isHTTPSOrigin(issuer), Self.isHTTPS(authorizationEndpoint),
              Self.isHTTPS(tokenEndpoint), Self.isHTTPS(jwksURI),
              authorizationEndpoint.host == issuer.host, tokenEndpoint.host == issuer.host,
              jwksURI.host == issuer.host, !scopesSupported.isEmpty,
              responseTypesSupported == ["code"], grantTypesSupported == ["authorization_code"],
              codeChallengeMethodsSupported == ["S256"] else { throw FountainAuthError.invalidIssuer }
        self.issuer = issuer; self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint; self.jwksURI = jwksURI
        self.scopesSupported = scopesSupported.sorted()
        self.responseTypesSupported = responseTypesSupported
        self.grantTypesSupported = grantTypesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
    }

    private static func isHTTPS(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && url.host?.isEmpty == false && url.user == nil && url.password == nil
    }

    private static func isHTTPSOrigin(_ url: URL) -> Bool {
        isHTTPS(url) && (url.path.isEmpty || url.path == "/") && url.query == nil && url.fragment == nil
    }
}

public struct FountainAuthProtectedResourceMetadata: Codable, Equatable, Sendable {
    public let resource: URL
    public let authorizationServers: [URL]
    public let scopesSupported: [String]
    public let bearerMethodsSupported: [String]

    public init(resource: URL, authorizationServer: URL, scopesSupported: [String]) throws {
        guard resource.scheme?.lowercased() == "https", resource.host?.isEmpty == false,
              authorizationServer.scheme?.lowercased() == "https", authorizationServer.host?.isEmpty == false,
              !scopesSupported.isEmpty else { throw FountainAuthError.invalidEndpoint }
        self.resource = resource; self.authorizationServers = [authorizationServer]
        self.scopesSupported = scopesSupported.sorted(); self.bearerMethodsSupported = ["header"]
    }
}

public struct FountainAuthClientRegistration: Codable, Equatable, Sendable {
    public let clientID: String
    public let redirectURIs: [URL]
    public let isPublicClient: Bool

    public init(clientID: String, redirectURIs: [URL], isPublicClient: Bool = true) throws {
        guard !clientID.isEmpty, !redirectURIs.isEmpty,
              redirectURIs.allSatisfy(Self.isExactRedirect) else { throw FountainAuthError.invalidClient }
        self.clientID = clientID; self.redirectURIs = redirectURIs; self.isPublicClient = isPublicClient
    }

    private static func isExactRedirect(_ url: URL) -> Bool {
        let scheme = url.scheme?.lowercased()
        let local = url.host == "localhost" || url.host?.hasSuffix(".localhost") == true
        return (scheme == "https" || (scheme == "http" && local)) && url.user == nil && url.password == nil && url.fragment == nil
    }
}

public struct FountainAuthAuthorizationRequest: Codable, Equatable, Sendable {
    public let clientID: String
    public let redirectURI: URL
    public let scope: [String]
    public let state: String
    public let codeChallenge: String
    public let codeChallengeMethod: String
    public let resource: URL
    public let correlationID: String
    public let expiresAt: Date

    public init(clientID: String, redirectURI: URL, scope: [String], state: String,
                codeChallenge: String, resource: URL, correlationID: String,
                expiresAt: Date) throws {
        guard !clientID.isEmpty, !state.isEmpty, !codeChallenge.isEmpty,
              !correlationID.isEmpty, Self.codeChallengeMethodIsS256(codeChallenge),
              resource.scheme?.lowercased() == "https", resource.host?.isEmpty == false,
              expiresAt > Date() else { throw FountainAuthError.invalidRequest }
        self.clientID = clientID; self.redirectURI = redirectURI
        self.scope = Array(Set(scope)).sorted(); self.state = state
        self.codeChallenge = codeChallenge; self.codeChallengeMethod = "S256"
        self.resource = resource; self.correlationID = correlationID; self.expiresAt = expiresAt
    }

    public func validate(against registration: FountainAuthClientRegistration,
                         supportedScopes: Set<String>, now: Date = Date()) throws {
        guard registration.clientID == clientID else { throw FountainAuthError.clientMismatch }
        guard registration.redirectURIs.contains(redirectURI) else { throw FountainAuthError.invalidRedirect }
        guard expiresAt > now else { throw FountainAuthError.codeExpired }
        guard scope.allSatisfy(supportedScopes.contains) else {
            throw FountainAuthError.scopeMissing(scope.first { !supportedScopes.contains($0) } ?? "unknown")
        }
    }

    public static func s256Challenge(verifier: String) -> String {
        base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    private static func codeChallengeMethodIsS256(_ value: String) -> Bool {
        value.count >= 43 && value.count <= 128 && value.allSatisfy { $0.isLetter || $0.isNumber || "-._~".contains($0) }
    }
}

public enum FountainAuthHumanDecision: Sendable { case approved, denied }

public struct FountainAuthAuthorizationCode: Sendable, Equatable {
    public let value: String
    public let expiresAt: Date
    public let evidence: FountainAuthGrantEvidence
}

public struct FountainAuthAccessToken: Sendable, Equatable {
    public let value: String
    public let evidence: FountainAuthGrantEvidence
}

/// Safe durable lineage. It intentionally has no bearer, refresh token,
/// authorization code, password, or private-key field.
public struct FountainAuthGrantEvidence: Codable, Equatable, Sendable {
    public let issuer: URL
    public let authorizationEventID: String
    public let subjectReference: String
    public let clientID: String
    public let resource: URL
    public let requestedScope: [String]
    public let grantedScope: [String]
    public let authorizedAt: Date
    public let expiresAt: Date
    public let authenticationMechanism: String
    public let policyVersion: String
    public let state: String
    public let sessionCorrelationID: String

    public init(issuer: URL, authorizationEventID: String, subjectReference: String,
                clientID: String, resource: URL, requestedScope: [String], grantedScope: [String],
                authorizedAt: Date, expiresAt: Date, authenticationMechanism: String,
                policyVersion: String, state: String, sessionCorrelationID: String) {
        self.issuer = issuer
        self.authorizationEventID = authorizationEventID
        self.subjectReference = subjectReference
        self.clientID = clientID
        self.resource = resource
        self.requestedScope = requestedScope
        self.grantedScope = grantedScope
        self.authorizedAt = authorizedAt
        self.expiresAt = expiresAt
        self.authenticationMechanism = authenticationMechanism
        self.policyVersion = policyVersion
        self.state = state
        self.sessionCorrelationID = sessionCorrelationID
    }
}

public struct FountainAuthValidatedGrant: Codable, Equatable, Sendable {
    public let issuer: URL
    public let subjectReference: String
    public let clientID: String
    public let resource: URL
    public let scope: [String]
    public let authorizationEventID: String
    public let tokenID: String
    public let expiresAt: Date
}

/// Host-owned persistence seam for safe authorization lineage. A FountainStore
/// adapter may implement this protocol without changing the kit's contract or
/// carrying bearer credentials into durable evidence.
public protocol FountainAuthGrantEvidenceLedger: Sendable {
    func append(_ evidence: FountainAuthGrantEvidence) async throws
    func evidence(for authorizationEventID: String) async throws -> FountainAuthGrantEvidence?
}

/// Deterministic fixture for contract tests. It is not FountainStore and must
/// never be used as durable or production authorization evidence.
public actor FountainAuthMemoryGrantEvidenceLedger: FountainAuthGrantEvidenceLedger {
    private var records: [String: FountainAuthGrantEvidence] = [:]

    public init() {}

    public func append(_ evidence: FountainAuthGrantEvidence) async throws {
        let key = evidence.authorizationEventID
        if let existing = records[key], existing != evidence { throw FountainAuthError.evidenceConflict }
        records[key] = evidence
    }

    public func evidence(for authorizationEventID: String) async throws -> FountainAuthGrantEvidence? {
        records[authorizationEventID]
    }
}

public struct FountainAuthSigningKey: Sendable {
    public let keyID: String
    fileprivate let privateKey: Curve25519.Signing.PrivateKey
    public let publicKey: Data

    public init(keyID: String, privateKey: Curve25519.Signing.PrivateKey) throws {
        guard !keyID.isEmpty else { throw FountainAuthError.keyUnavailable }
        self.keyID = keyID; self.privateKey = privateKey; self.publicKey = privateKey.publicKey.rawRepresentation
    }
}

public protocol FountainAuthSigningKeyStore: Sendable {
    func activeSigningKey() async throws -> FountainAuthSigningKey
    func verificationKeys(now: Date) async throws -> [String: Data]
}

public extension FountainAuthSigningKeyStore {
    func verificationKeys() async throws -> [String: Data] {
        try await verificationKeys(now: Date())
    }
}

public enum FountainAuthSigningKeyState: String, Codable, Equatable, Sendable {
    case active
    case verificationOverlap
    case retired
    case compromised
}

public struct FountainAuthSigningKeyLifecycleRecord: Codable, Equatable, Sendable {
    public let reference: FountainAuthSecretKeyReference
    public let state: FountainAuthSigningKeyState
    public let activatedAt: Date
    public let verificationUntil: Date?
    public let stateChangedAt: Date

    public init(reference: FountainAuthSecretKeyReference,
                state: FountainAuthSigningKeyState,
                activatedAt: Date,
                verificationUntil: Date? = nil,
                stateChangedAt: Date) throws {
        if state == .verificationOverlap {
            guard let verificationUntil, verificationUntil > stateChangedAt else {
                throw FountainAuthError.invalidKeyLifecycle
            }
        } else if verificationUntil != nil {
            throw FountainAuthError.invalidKeyLifecycle
        }
        self.reference = reference
        self.state = state
        self.activatedAt = activatedAt
        self.verificationUntil = verificationUntil
        self.stateChangedAt = stateChangedAt
    }
}

public protocol FountainAuthSigningKeyLifecycleStore: Sendable {
    func load() async throws -> [FountainAuthSigningKeyLifecycleRecord]
    func save(_ records: [FountainAuthSigningKeyLifecycleRecord]) async throws
}

public actor FountainAuthMemorySigningKeyLifecycleStore: FountainAuthSigningKeyLifecycleStore {
    private var records: [FountainAuthSigningKeyLifecycleRecord]

    public init(records: [FountainAuthSigningKeyLifecycleRecord] = []) {
        self.records = records
    }

    public func load() async throws -> [FountainAuthSigningKeyLifecycleRecord] { records }
    public func save(_ records: [FountainAuthSigningKeyLifecycleRecord]) async throws { self.records = records }
}

public actor FountainAuthFileSigningKeyLifecycleStore: FountainAuthSigningKeyLifecycleStore {
    private let fileURL: URL

    public init(fileURL: URL) throws {
        guard fileURL.isFileURL else { throw FountainAuthError.invalidRequest }
        self.fileURL = fileURL
    }

    public func load() async throws -> [FountainAuthSigningKeyLifecycleRecord] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        return try JSONDecoder().decode([FountainAuthSigningKeyLifecycleRecord].self,
                                        from: Data(contentsOf: fileURL))
    }

    public func save(_ records: [FountainAuthSigningKeyLifecycleRecord]) async throws {
        try validateLifecycleRecords(records)
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try JSONEncoder().encode(records).write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }
}

private func validateLifecycleRecords(_ records: [FountainAuthSigningKeyLifecycleRecord]) throws {
    guard Set(records.map { $0.reference.keyID }).count == records.count,
          records.filter({ $0.state == .active }).count <= 1 else {
        throw FountainAuthError.invalidKeyLifecycle
    }
}

/// Opaque host-selected SecretStore location for one EdDSA signing key.
/// The key material itself never appears in this reference or any evidence.
public struct FountainAuthSecretKeyReference: Codable, Equatable, Hashable, Sendable {
    public let keyID: String
    public let account: String

    public init(keyID: String, account: String) throws {
        guard !keyID.isEmpty, !account.isEmpty,
              !keyID.contains(where: { $0.isWhitespace || $0 == "\n" || $0 == "\r" }),
              !account.contains(where: { $0 == "\n" || $0 == "\r" }) else {
            throw FountainAuthError.invalidSecretReference
        }
        self.keyID = keyID; self.account = account
    }
}

/// SecretStore owns private-key custody. This actor owns only lifecycle
/// transitions and references; durable lifecycle metadata never contains key bytes.
public actor FountainAuthSecretStoreKeyStore: FountainAuthSigningKeyStore {
    private let store: any SecretStore
    private let lifecycleStore: any FountainAuthSigningKeyLifecycleStore
    private var records: [FountainAuthSigningKeyLifecycleRecord]

    public init(store: any SecretStore,
                active: FountainAuthSecretKeyReference,
                verification: [FountainAuthSecretKeyReference]? = nil) throws {
        let now = Date()
        let refs = verification ?? [active]
        guard refs.contains(active), Set(refs).count == refs.count else {
            throw FountainAuthError.invalidSecretReference
        }
        self.store = store
        self.lifecycleStore = FountainAuthMemorySigningKeyLifecycleStore()
        self.records = try refs.map { ref in
            if ref == active {
                return try FountainAuthSigningKeyLifecycleRecord(
                    reference: ref, state: .active, activatedAt: now, stateChangedAt: now)
            }
            return try FountainAuthSigningKeyLifecycleRecord(
                reference: ref, state: .verificationOverlap, activatedAt: now,
                verificationUntil: now.addingTimeInterval(600), stateChangedAt: now)
        }
    }

    public init(store: any SecretStore,
                initialActive: FountainAuthSecretKeyReference,
                lifecycleStore: any FountainAuthSigningKeyLifecycleStore,
                now: Date = Date()) async throws {
        self.store = store
        self.lifecycleStore = lifecycleStore
        let existing = try await lifecycleStore.load()
        if existing.isEmpty {
            guard try store.retrieveSecret(for: initialActive.account) != nil else {
                throw FountainAuthError.keyUnavailable
            }
            let initial = try FountainAuthSigningKeyLifecycleRecord(
                reference: initialActive, state: .active, activatedAt: now, stateChangedAt: now)
            self.records = [initial]
            try await lifecycleStore.save([initial])
        } else {
            try validateLifecycleRecords(existing)
            self.records = existing
        }
    }

    public func activeSigningKey() async throws -> FountainAuthSigningKey {
        guard let active = records.first(where: { $0.state == .active }) else {
            throw FountainAuthError.keyUnavailable
        }
        return try load(active.reference)
    }

    public func verificationKeys(now: Date) async throws -> [String: Data] {
        var keys: [String: Data] = [:]
        for record in records {
            let admitted: Bool
            switch record.state {
            case .active:
                admitted = true
            case .verificationOverlap:
                admitted = record.verificationUntil.map { now < $0 } == true
            case .retired, .compromised:
                admitted = false
            }
            if admitted {
                let key = try load(record.reference)
                keys[key.keyID] = key.publicKey
            }
        }
        return keys
    }

    public func rotate(to reference: FountainAuthSecretKeyReference,
                       overlapUntil: Date,
                       now: Date = Date()) async throws {
        guard overlapUntil > now else { throw FountainAuthError.invalidKeyLifecycle }
        guard !records.contains(where: { $0.reference == reference }) else {
            throw FountainAuthError.keyAlreadyExists
        }
        guard try store.retrieveSecret(for: reference.account) == nil else {
            throw FountainAuthError.keyAlreadyExists
        }
        let privateKey = Curve25519.Signing.PrivateKey()
        do {
            try store.storeSecret(privateKey.rawRepresentation, for: reference.account)
        } catch {
            throw FountainAuthError.secretStoreUnavailable
        }

        var next: [FountainAuthSigningKeyLifecycleRecord] = []
        for record in records {
            if record.state == .active {
                next.append(try FountainAuthSigningKeyLifecycleRecord(
                    reference: record.reference,
                    state: .verificationOverlap,
                    activatedAt: record.activatedAt,
                    verificationUntil: overlapUntil,
                    stateChangedAt: now))
            } else {
                next.append(record)
            }
        }
        next.append(try FountainAuthSigningKeyLifecycleRecord(
            reference: reference, state: .active, activatedAt: now, stateChangedAt: now))
        try await persist(next)
    }

    public func rotate(to reference: FountainAuthSecretKeyReference) async throws {
        let now = Date()
        try await rotate(to: reference, overlapUntil: now.addingTimeInterval(600), now: now)
    }

    public func retireExpired(now: Date = Date()) async throws {
        var changed = false
        var next: [FountainAuthSigningKeyLifecycleRecord] = []
        for record in records {
            if record.state == .verificationOverlap,
               let until = record.verificationUntil,
               now >= until {
                next.append(try FountainAuthSigningKeyLifecycleRecord(
                    reference: record.reference,
                    state: .retired,
                    activatedAt: record.activatedAt,
                    stateChangedAt: now))
                changed = true
            } else {
                next.append(record)
            }
        }
        if changed { try await persist(next) }
    }

    public func markCompromised(keyID: String, now: Date = Date()) async throws {
        guard let target = records.first(where: { $0.reference.keyID == keyID }) else {
            throw FountainAuthError.keyUnavailable
        }
        var next: [FountainAuthSigningKeyLifecycleRecord] = []
        for record in records {
            if record.reference.keyID == keyID {
                next.append(try FountainAuthSigningKeyLifecycleRecord(
                    reference: record.reference,
                    state: .compromised,
                    activatedAt: record.activatedAt,
                    stateChangedAt: now))
            } else {
                next.append(record)
            }
        }
        try await persist(next)
        try? store.deleteSecret(for: target.reference.account)
    }

    public func recover(with reference: FountainAuthSecretKeyReference,
                        now: Date = Date()) async throws {
        guard records.first(where: { $0.state == .active }) == nil else {
            throw FountainAuthError.invalidKeyLifecycle
        }
        guard !records.contains(where: { $0.reference == reference }) else {
            throw FountainAuthError.keyAlreadyExists
        }
        guard try store.retrieveSecret(for: reference.account) == nil else {
            throw FountainAuthError.keyAlreadyExists
        }
        let privateKey = Curve25519.Signing.PrivateKey()
        do {
            try store.storeSecret(privateKey.rawRepresentation, for: reference.account)
        } catch {
            throw FountainAuthError.secretStoreUnavailable
        }
        var next = records
        next.append(try FountainAuthSigningKeyLifecycleRecord(
            reference: reference, state: .active, activatedAt: now, stateChangedAt: now))
        try await persist(next)
    }

    public func lifecycle() -> [FountainAuthSigningKeyLifecycleRecord] {
        records
    }

    private func persist(_ next: [FountainAuthSigningKeyLifecycleRecord]) async throws {
        try validateLifecycleRecords(next)
        try await lifecycleStore.save(next)
        records = next
    }

    private func load(_ reference: FountainAuthSecretKeyReference) throws -> FountainAuthSigningKey {
        do {
            guard let material = try store.retrieveSecret(for: reference.account), !material.isEmpty else {
                throw FountainAuthError.keyUnavailable
            }
            guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: material) else {
                throw FountainAuthError.invalidStoredKey
            }
            return try FountainAuthSigningKey(keyID: reference.keyID, privateKey: privateKey)
        } catch let error as FountainAuthError {
            throw error
        } catch {
            throw FountainAuthError.secretStoreUnavailable
        }
    }
}

/// Test/fixture custody seam. Production consumers must replace this with a
/// SecretStore-backed host adapter before operational use; the adapter above
/// is the reusable custody boundary and still requires host authorization.
public actor FountainAuthMemoryKeyStore: FountainAuthSigningKeyStore {
    private var active: FountainAuthSigningKey
    private var verification: [String: Data]

    public init(keyID: String = "auth-test-1") throws {
        let key = try FountainAuthSigningKey(keyID: keyID, privateKey: Curve25519.Signing.PrivateKey())
        active = key; verification = [key.keyID: key.publicKey]
    }

    public func activeSigningKey() async throws -> FountainAuthSigningKey { active }
    public func verificationKeys(now: Date) async throws -> [String: Data] { verification }

    public func rotate(keyID: String) throws {
        let key = try FountainAuthSigningKey(keyID: keyID, privateKey: Curve25519.Signing.PrivateKey())
        active = key; verification[key.keyID] = key.publicKey
    }
}


public struct FountainAuthStoredAuthorizationCode: Codable, Equatable, Sendable {
    public let request: FountainAuthAuthorizationRequest
    public let subjectReference: String
    public let authenticationMechanism: String
    public let approvedAt: Date
    public let authorizationEventID: String
    public let expiresAt: Date

    public init(request: FountainAuthAuthorizationRequest,
                subjectReference: String,
                authenticationMechanism: String,
                approvedAt: Date,
                authorizationEventID: String,
                expiresAt: Date) {
        self.request = request
        self.subjectReference = subjectReference
        self.authenticationMechanism = authenticationMechanism
        self.approvedAt = approvedAt
        self.authorizationEventID = authorizationEventID
        self.expiresAt = expiresAt
    }
}

public protocol FountainAuthAuthorityStateStore: Sendable {
    func register(client: FountainAuthClientRegistration, issuer: URL) async throws
    func client(issuer: URL, clientID: String) async throws -> FountainAuthClientRegistration?
    func storeAuthorizationCode(_ record: FountainAuthStoredAuthorizationCode,
                                issuer: URL,
                                codeDigest: String) async throws
    func consumeAuthorizationCode(issuer: URL,
                                  codeDigest: String) async throws -> FountainAuthStoredAuthorizationCode?
    func revokeTokenID(_ tokenID: String, issuer: URL) async throws
    func isTokenRevoked(_ tokenID: String, issuer: URL) async throws -> Bool
    func admitIssuer(_ issuer: URL) async throws
    func admittedIssuers() async throws -> [URL]
}

private struct FountainAuthAuthorityStateSnapshot: Codable, Sendable {
    var clients: [String: [String: FountainAuthClientRegistration]] = [:]
    var authorizationCodes: [String: [String: FountainAuthStoredAuthorizationCode]] = [:]
    var revokedTokenIDs: [String: Set<String>] = [:]
    var admittedIssuerStrings: Set<String> = []
}

public actor FountainAuthMemoryAuthorityStateStore: FountainAuthAuthorityStateStore {
    private var snapshot = FountainAuthAuthorityStateSnapshot()

    public init() {}

    public func register(client: FountainAuthClientRegistration, issuer: URL) async throws {
        let key = try canonicalIssuerString(issuer)
        snapshot.clients[key, default: [:]][client.clientID] = client
    }

    public func client(issuer: URL, clientID: String) async throws -> FountainAuthClientRegistration? {
        snapshot.clients[try canonicalIssuerString(issuer)]?[clientID]
    }

    public func storeAuthorizationCode(_ record: FountainAuthStoredAuthorizationCode,
                                       issuer: URL,
                                       codeDigest: String) async throws {
        let key = try canonicalIssuerString(issuer)
        guard snapshot.authorizationCodes[key]?[codeDigest] == nil else {
            throw FountainAuthError.authorityStateConflict
        }
        snapshot.authorizationCodes[key, default: [:]][codeDigest] = record
    }

    public func consumeAuthorizationCode(issuer: URL,
                                         codeDigest: String) async throws -> FountainAuthStoredAuthorizationCode? {
        let key = try canonicalIssuerString(issuer)
        return snapshot.authorizationCodes[key]?.removeValue(forKey: codeDigest)
    }

    public func revokeTokenID(_ tokenID: String, issuer: URL) async throws {
        let key = try canonicalIssuerString(issuer)
        snapshot.revokedTokenIDs[key, default: []].insert(tokenID)
    }

    public func isTokenRevoked(_ tokenID: String, issuer: URL) async throws -> Bool {
        snapshot.revokedTokenIDs[try canonicalIssuerString(issuer)]?.contains(tokenID) == true
    }

    public func admitIssuer(_ issuer: URL) async throws {
        snapshot.admittedIssuerStrings.insert(try canonicalIssuerString(issuer))
    }

    public func admittedIssuers() async throws -> [URL] {
        snapshot.admittedIssuerStrings.sorted().compactMap(URL.init(string:))
    }
}

public actor FountainAuthFileAuthorityStateStore: FountainAuthAuthorityStateStore {
    private let fileURL: URL
    private var snapshot: FountainAuthAuthorityStateSnapshot

    public init(fileURL: URL) throws {
        guard fileURL.isFileURL else { throw FountainAuthError.invalidRequest }
        self.fileURL = fileURL
        if FileManager.default.fileExists(atPath: fileURL.path) {
            let data = try Data(contentsOf: fileURL)
            self.snapshot = try JSONDecoder().decode(FountainAuthAuthorityStateSnapshot.self, from: data)
        } else {
            self.snapshot = FountainAuthAuthorityStateSnapshot()
        }
    }

    public func register(client: FountainAuthClientRegistration, issuer: URL) async throws {
        let key = try canonicalIssuerString(issuer)
        snapshot.clients[key, default: [:]][client.clientID] = client
        try persist()
    }

    public func client(issuer: URL, clientID: String) async throws -> FountainAuthClientRegistration? {
        snapshot.clients[try canonicalIssuerString(issuer)]?[clientID]
    }

    public func storeAuthorizationCode(_ record: FountainAuthStoredAuthorizationCode,
                                       issuer: URL,
                                       codeDigest: String) async throws {
        let key = try canonicalIssuerString(issuer)
        guard snapshot.authorizationCodes[key]?[codeDigest] == nil else {
            throw FountainAuthError.authorityStateConflict
        }
        snapshot.authorizationCodes[key, default: [:]][codeDigest] = record
        try persist()
    }

    public func consumeAuthorizationCode(issuer: URL,
                                         codeDigest: String) async throws -> FountainAuthStoredAuthorizationCode? {
        let key = try canonicalIssuerString(issuer)
        guard let record = snapshot.authorizationCodes[key]?.removeValue(forKey: codeDigest) else { return nil }
        try persist()
        return record
    }

    public func revokeTokenID(_ tokenID: String, issuer: URL) async throws {
        let key = try canonicalIssuerString(issuer)
        snapshot.revokedTokenIDs[key, default: []].insert(tokenID)
        try persist()
    }

    public func isTokenRevoked(_ tokenID: String, issuer: URL) async throws -> Bool {
        snapshot.revokedTokenIDs[try canonicalIssuerString(issuer)]?.contains(tokenID) == true
    }

    public func admitIssuer(_ issuer: URL) async throws {
        snapshot.admittedIssuerStrings.insert(try canonicalIssuerString(issuer))
        try persist()
    }

    public func admittedIssuers() async throws -> [URL] {
        snapshot.admittedIssuerStrings.sorted().compactMap(URL.init(string:))
    }

    private func persist() throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(snapshot)
        try data.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }
}

private func authorizationCodeDigest(_ value: String) -> String {
    Data(SHA256.hash(data: Data(value.utf8))).map { String(format: "%02x", $0) }.joined()
}

private func canonicalIssuerString(_ issuer: URL) throws -> String {
    guard issuer.scheme?.lowercased() == "https",
          issuer.host?.isEmpty == false,
          (issuer.path.isEmpty || issuer.path == "/"),
          issuer.query == nil,
          issuer.fragment == nil,
          issuer.user == nil,
          issuer.password == nil else {
        throw FountainAuthError.invalidIssuer
    }
    return issuer.absoluteString.hasSuffix("/")
        ? String(issuer.absoluteString.dropLast())
        : issuer.absoluteString
}

public actor FountainAuthAuthorizationServer {
    public let metadata: FountainAuthServerMetadata
    public let policyVersion: String
    private let keyStore: any FountainAuthSigningKeyStore
    private let evidenceLedger: (any FountainAuthGrantEvidenceLedger)?
    private let stateStore: any FountainAuthAuthorityStateStore
    private let codeLifetime: TimeInterval
    private let tokenLifetime: TimeInterval

    public init(metadata: FountainAuthServerMetadata,
                keyStore: any FountainAuthSigningKeyStore,
                evidenceLedger: (any FountainAuthGrantEvidenceLedger)? = nil,
                stateStore: (any FountainAuthAuthorityStateStore)? = nil,
                policyVersion: String = "fountain-auth-policy-v1",
                codeLifetime: TimeInterval = 120,
                tokenLifetime: TimeInterval = 600) throws {
        guard codeLifetime > 0, tokenLifetime > 0, !policyVersion.isEmpty else {
            throw FountainAuthError.invalidRequest
        }
        self.metadata = metadata
        self.keyStore = keyStore
        self.evidenceLedger = evidenceLedger
        self.stateStore = stateStore ?? FountainAuthMemoryAuthorityStateStore()
        self.policyVersion = policyVersion
        self.codeLifetime = codeLifetime
        self.tokenLifetime = tokenLifetime
    }

    public func register(_ client: FountainAuthClientRegistration) async throws {
        try await stateStore.register(client: client, issuer: metadata.issuer)
    }

    public func begin(_ request: FountainAuthAuthorizationRequest,
                      subjectReference: String,
                      authenticationMechanism: String,
                      decision: FountainAuthHumanDecision,
                      now: Date = Date()) async throws -> FountainAuthAuthorizationCode {
        guard decision == .approved else { throw FountainAuthError.authorizationDenied }
        guard !subjectReference.isEmpty, !authenticationMechanism.isEmpty,
              let registration = try await stateStore.client(issuer: metadata.issuer,
                                                             clientID: request.clientID) else {
            throw FountainAuthError.invalidClient
        }
        try request.validate(against: registration,
                             supportedScopes: Set(metadata.scopesSupported),
                             now: now)
        let value = randomOpaqueValue()
        let expires = min(request.expiresAt, now.addingTimeInterval(codeLifetime))
        let authorizationEventID = UUID().uuidString
        let evidence = FountainAuthGrantEvidence(
            issuer: metadata.issuer,
            authorizationEventID: authorizationEventID,
            subjectReference: subjectReference,
            clientID: request.clientID,
            resource: request.resource,
            requestedScope: request.scope,
            grantedScope: request.scope,
            authorizedAt: now,
            expiresAt: expires,
            authenticationMechanism: authenticationMechanism,
            policyVersion: policyVersion,
            state: "authorized",
            sessionCorrelationID: request.correlationID)
        let record = FountainAuthStoredAuthorizationCode(
            request: request,
            subjectReference: subjectReference,
            authenticationMechanism: authenticationMechanism,
            approvedAt: now,
            authorizationEventID: authorizationEventID,
            expiresAt: expires)
        try await stateStore.storeAuthorizationCode(record,
                                                    issuer: metadata.issuer,
                                                    codeDigest: authorizationCodeDigest(value))
        return FountainAuthAuthorizationCode(value: value, expiresAt: expires, evidence: evidence)
    }

    public func redeem(code value: String,
                       clientID: String,
                       redirectURI: URL,
                       verifier: String,
                       resource: URL,
                       now: Date = Date()) async throws -> FountainAuthAccessToken {
        guard let record = try await stateStore.consumeAuthorizationCode(
            issuer: metadata.issuer,
            codeDigest: authorizationCodeDigest(value)) else {
            throw FountainAuthError.unknownCode
        }
        guard record.expiresAt > now else { throw FountainAuthError.codeExpired }
        guard record.request.clientID == clientID,
              record.request.redirectURI == redirectURI else {
            throw FountainAuthError.invalidRedirect
        }
        guard record.request.resource == resource else {
            throw FountainAuthError.resourceMismatch
        }
        guard FountainAuthAuthorizationRequest.s256Challenge(verifier: verifier) ==
                record.request.codeChallenge else {
            throw FountainAuthError.invalidPKCE
        }

        let key = try await keyStore.activeSigningKey()
        let tokenID = UUID().uuidString
        let expires = now.addingTimeInterval(tokenLifetime)
        let header = ["alg": "EdDSA", "kid": key.keyID, "typ": "at+jwt"]
        let payload: [String: Any] = [
            "iss": metadata.issuer.absoluteString,
            "sub": record.subjectReference,
            "client_id": clientID,
            "aud": resource.absoluteString,
            "scope": record.request.scope.joined(separator: " "),
            "iat": now.timeIntervalSince1970,
            "exp": expires.timeIntervalSince1970,
            "jti": tokenID,
            "authorization_event": record.authorizationEventID
        ]
        let encodedHeader = try jsonBase64(header)
        let encodedPayload = try jsonBase64(payload)
        let signingInput = Data("\(encodedHeader).\(encodedPayload)".utf8)
        let signature = try key.privateKey.signature(for: signingInput)
        let grant = FountainAuthGrantEvidence(
            issuer: metadata.issuer,
            authorizationEventID: record.authorizationEventID,
            subjectReference: record.subjectReference,
            clientID: clientID,
            resource: resource,
            requestedScope: record.request.scope,
            grantedScope: record.request.scope,
            authorizedAt: record.approvedAt,
            expiresAt: expires,
            authenticationMechanism: record.authenticationMechanism,
            policyVersion: policyVersion,
            state: "issued",
            sessionCorrelationID: record.request.correlationID)
        try await evidenceLedger?.append(grant)
        return FountainAuthAccessToken(
            value: "\(encodedHeader).\(encodedPayload).\(base64URL(signature))",
            evidence: grant)
    }

    public func validate(_ token: FountainAuthAccessToken,
                         resource: URL,
                         requiredScope: String,
                         now: Date = Date()) async throws -> FountainAuthValidatedGrant {
        let parts = token.value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let header = jsonObject(parts[0]),
              let payload = jsonObject(parts[1]),
              let kid = header["kid"] as? String,
              let signature = Data(base64URL: String(parts[2])),
              let signingInput = "\(parts[0]).\(parts[1])".data(using: .utf8),
              let issuer = payload["iss"] as? String,
              issuer == metadata.issuer.absoluteString,
              let audience = payload["aud"] as? String,
              audience == resource.absoluteString,
              let subject = payload["sub"] as? String,
              !subject.isEmpty,
              let clientID = payload["client_id"] as? String,
              let scopeText = payload["scope"] as? String,
              let tokenID = payload["jti"] as? String,
              let authorizationEventID = payload["authorization_event"] as? String,
              let expiry = payload["exp"] as? NSNumber else {
            throw FountainAuthError.invalidToken
        }
        guard let publicData = try await keyStore.verificationKeys(now: now)[kid],
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicData),
              publicKey.isValidSignature(signature, for: signingInput) else {
            throw FountainAuthError.invalidToken
        }
        guard Date(timeIntervalSince1970: expiry.doubleValue) > now else {
            throw FountainAuthError.tokenExpired
        }
        guard try await !stateStore.isTokenRevoked(tokenID, issuer: metadata.issuer) else {
            throw FountainAuthError.tokenRevoked
        }
        let scopes = scopeText.split(separator: " ").map(String.init)
        guard scopes.contains(requiredScope) else {
            throw FountainAuthError.scopeMissing(requiredScope)
        }
        return FountainAuthValidatedGrant(
            issuer: metadata.issuer,
            subjectReference: subject,
            clientID: clientID,
            resource: resource,
            scope: scopes,
            authorizationEventID: authorizationEventID,
            tokenID: tokenID,
            expiresAt: Date(timeIntervalSince1970: expiry.doubleValue))
    }

    public func revoke(_ token: FountainAuthAccessToken) async throws {
        let parts = token.value.split(separator: ".")
        guard parts.count == 3,
              let payload = jsonObject(parts[1]),
              let issuer = payload["iss"] as? String,
              issuer == metadata.issuer.absoluteString,
              let tokenID = payload["jti"] as? String else {
            throw FountainAuthError.invalidToken
        }
        try await stateStore.revokeTokenID(tokenID, issuer: metadata.issuer)
    }
}

private func randomOpaqueValue() -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "") }

private func base64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func jsonBase64(_ object: Any) throws -> String {
    base64URL(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
}

private func jsonObject(_ segment: Substring) -> [String: Any]? {
    guard let data = Data(base64URL: String(segment)) else { return nil }
    return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
}

private extension Data {
    init?(base64URL value: String) {
        var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        text += String(repeating: "=", count: (4 - text.count % 4) % 4)
        self.init(base64Encoded: text)
    }
}


/// Exact, fail-closed resolver for multiple writer-domain authorization authorities.
/// A shared process may host several domains; it never gains a default/global authority.
public actor FountainAuthDomainRuntime {
    private let stateStore: any FountainAuthAuthorityStateStore
    private var authorities: [String: FountainAuthAuthorizationServer] = [:]

    public init(stateStore: (any FountainAuthAuthorityStateStore)? = nil) {
        self.stateStore = stateStore ?? FountainAuthMemoryAuthorityStateStore()
    }

    public func admit(issuer: URL, authority: FountainAuthAuthorizationServer) async throws {
        let canonical = try canonicalIssuerString(issuer)
        guard authority.metadata.issuer == issuer else { throw FountainAuthError.issuerMismatch }
        if authorities[canonical] != nil { throw FountainAuthError.invalidIssuer }
        try await stateStore.admitIssuer(issuer)
        authorities[canonical] = authority
    }

    public func bind(issuer: URL, authority: FountainAuthAuthorizationServer) async throws {
        let canonical = try canonicalIssuerString(issuer)
        guard authority.metadata.issuer == issuer else { throw FountainAuthError.issuerMismatch }
        let admitted = try await stateStore.admittedIssuers().map(canonicalIssuerString)
        guard admitted.contains(canonical) else { throw FountainAuthError.invalidIssuer }
        authorities[canonical] = authority
    }

    public func authority(for issuer: URL) throws -> FountainAuthAuthorizationServer {
        let canonical = try canonicalIssuerString(issuer)
        guard let authority = authorities[canonical] else { throw FountainAuthError.invalidIssuer }
        return authority
    }

    public func admittedIssuers() async throws -> [String] {
        try await stateStore.admittedIssuers().map(canonicalIssuerString).sorted()
    }
}

/// A protected resource may translate an already validated grant into this typed
/// read-only admission. The package does not execute the host capability.
public struct FountainAuthHostDescribeAdmission: Equatable, Sendable {
    public static let capability = "host.describe"

    public let issuer: URL
    public let subjectReference: String
    public let clientID: String
    public let resource: URL
    public let authorizationEventID: String
    public let expiresAt: Date

    public init(validatedGrant: FountainAuthValidatedGrant) throws {
        guard validatedGrant.scope.contains(Self.capability) else {
            throw FountainAuthError.scopeMissing(Self.capability)
        }
        self.issuer = validatedGrant.issuer
        self.subjectReference = validatedGrant.subjectReference
        self.clientID = validatedGrant.clientID
        self.resource = validatedGrant.resource
        self.authorizationEventID = validatedGrant.authorizationEventID
        self.expiresAt = validatedGrant.expiresAt
    }
}
