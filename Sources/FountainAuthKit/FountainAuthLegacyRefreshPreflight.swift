import Foundation

/// Read-only compatibility preflight for the existing Host issuer's rotating
/// refresh-family JSON. This checks a migration source; it neither imports an
/// authority nor changes grants, keys, registries, or bearer credentials.
public enum FountainAuthLegacyRefreshPreflight {
    public struct Receipt: Equatable, Sendable {
        public let clients: Int
        public let refreshFamilies: Int
        public let revokedFamilies: Int
        public let authorizationEvents: Int
    }

    private struct LegacyFamily: Codable {
        let familyID: String
        let clientID: String
        let resource: URL
        let subjectReference: String
        let grantedScope: [String]
        let authorizedAt: Date
        let expiresAt: Date
        let authorizationEventID: String
        let authenticationMechanism: String
        let correlationID: String
        let currentDigest: String
        let consumedDigests: [String]
        let revoked: Bool
    }

    /// Both inputs are bytes supplied by the caller from the *same* frozen
    /// legacy registry snapshot. An issuer binding must be independently
    /// established by the Host; legacy records do not encode their issuer.
    public static func inspect(clientsJSON: Data, refreshFamiliesJSON: Data,
                               permittedResource: URL) throws -> Receipt {
        guard permittedResource.scheme?.lowercased() == "https",
              permittedResource.host?.isEmpty == false,
              clientsJSON.count <= 16_777_216,
              refreshFamiliesJSON.count <= 16_777_216 else {
            throw FountainAuthError.invalidRequest
        }
        let decoder = JSONDecoder()
        let clients = try decoder.decode([FountainAuthClientRegistration].self,
                                         from: clientsJSON)
        let families = try decoder.decode([LegacyFamily].self,
                                          from: refreshFamiliesJSON)
        let registered = Set(clients.map(\.clientID))
        guard registered.count == clients.count else {
            throw FountainAuthError.authorityStateConflict
        }
        var familyIDs = Set<String>()
        var eventIDs = Set<String>()
        var allDigests = Set<String>()
        for family in families {
            guard !family.familyID.isEmpty,
                  familyIDs.insert(family.familyID).inserted,
                  registered.contains(family.clientID),
                  family.resource == permittedResource,
                  !family.subjectReference.isEmpty,
                  !family.grantedScope.isEmpty,
                  family.grantedScope.allSatisfy({ !$0.isEmpty }),
                  family.expiresAt > family.authorizedAt,
                  !family.authorizationEventID.isEmpty,
                  !family.authenticationMechanism.isEmpty,
                  !family.correlationID.isEmpty,
                  family.currentDigest.count == 64,
                  family.currentDigest.utf8.allSatisfy({
                      ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
                  }),
                  allDigests.insert(family.currentDigest).inserted else {
                throw FountainAuthError.authorityStateConflict
            }
            eventIDs.insert(family.authorizationEventID)
            for digest in family.consumedDigests {
                guard digest.count == 64,
                      digest.utf8.allSatisfy({
                          ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
                      }),
                      allDigests.insert(digest).inserted else {
                    throw FountainAuthError.authorityStateConflict
                }
            }
        }
        return Receipt(
            clients: clients.count,
            refreshFamilies: families.count,
            revokedFamilies: families.filter(\.revoked).count,
            authorizationEvents: eventIDs.count)
    }
}
