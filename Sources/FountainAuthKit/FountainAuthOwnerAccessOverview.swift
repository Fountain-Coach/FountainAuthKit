import Foundation

/// Read-only owner projection of the *current* one-writer issuer snapshot.
/// The transport must authenticate the owner before calling this reader.
/// This value deliberately contains no refresh digests, consumed token
/// digests, bearer, authorization code, signing key or password.
public struct FountainAuthOwnerAccessOverview: Codable, Equatable, Sendable {
    public struct Grant: Codable, Equatable, Sendable {
        public let familyID: String
        public let authorizationEventID: String
        public let clientID: String
        public let resource: URL
        public let scopes: [String]
        public let authorizedAt: Date
        public let expiresAt: Date
        public let status: String
    }

    public let issuer: URL
    public let clientIDs: [String]
    public let grants: [Grant]
    public let observedAt: Date
}

/// Separate read-side process or a fresh request can inspect the issuer's
/// current durable state. Unknown/corrupt/unprotected snapshots refuse.
public struct FountainAuthFileOwnerAccessReader: Sendable {
    public let fileURL: URL

    public init(fileURL: URL) throws {
        guard fileURL.isFileURL, fileURL.path.hasPrefix("/") else {
            throw FountainAuthError.invalidRequest
        }
        self.fileURL = fileURL
    }

    public func read(issuer: URL, now: Date = Date()) throws -> FountainAuthOwnerAccessOverview {
        guard issuer.scheme?.lowercased() == "https", issuer.host?.isEmpty == false,
              issuer.path.isEmpty || issuer.path == "/",
              issuer.user == nil, issuer.password == nil,
              issuer.query == nil, issuer.fragment == nil else {
            throw FountainAuthError.invalidIssuer
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let permissions = attributes[.posixPermissions] as? NSNumber,
              permissions.intValue & 0o077 == 0 else {
            throw FountainAuthError.authorizationDenied
        }
        let bytes = try Data(contentsOf: fileURL)
        let state = try JSONDecoder().decode(ReadSnapshot.self, from: bytes)
        let key = issuer.absoluteString.hasSuffix("/")
            ? String(issuer.absoluteString.dropLast()) : issuer.absoluteString
        guard let clients = state.clients[key] else {
            throw FountainAuthError.authorizationDenied
        }
        let events = state.issuedAuthorizationEvents[key] ?? [:]
        let families = state.refreshFamilies[key] ?? [:]
        var grants: [FountainAuthOwnerAccessOverview.Grant] = []
        for family in families.values {
            guard clients[family.clientID] != nil,
                  let event = events[family.authorizationEventID],
                  event.clientID == family.clientID, event.resource == family.resource else {
                throw FountainAuthError.authorityStateConflict
            }
            let status: String
            if event.revoked || family.revoked {
                status = "revoked"
            } else if family.expiresAt <= now {
                status = "expired"
            } else {
                status = "active"
            }
            let grant = FountainAuthOwnerAccessOverview.Grant(
                familyID: family.familyID,
                authorizationEventID: family.authorizationEventID,
                clientID: family.clientID,
                resource: family.resource,
                scopes: family.grantedScope.sorted(),
                authorizedAt: family.authorizedAt,
                expiresAt: family.expiresAt,
                status: status)
            grants.append(grant)
        }
        grants.sort { a, b in
            if a.clientID == b.clientID {
                return a.authorizationEventID < b.authorizationEventID
            }
            return a.clientID < b.clientID
        }
        return .init(issuer: issuer, clientIDs: clients.keys.sorted(),
                     grants: grants, observedAt: now)
    }
}

private struct ReadSnapshot: Decodable {
    struct Event: Decodable {
        let authorizationEventID: String
        let clientID: String
        let resource: URL
        let revoked: Bool
    }

    let clients: [String: [String: FountainAuthClientRegistration]]
    let refreshFamilies: [String: [String: FountainAuthRefreshFamily]]
    let issuedAuthorizationEvents: [String: [String: Event]]
}
