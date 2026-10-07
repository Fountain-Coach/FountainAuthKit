# Authority map

| Concern | Authority |
| --- | --- |
| Principal authentication fact | admitted authentication adapter |
| Capability grant | writer-domain FountainAuthKit authority |
| Client registration | writer-domain authority |
| Issuer identity | admitted writer domain |
| Protected-resource admission | protected resource |
| `host.describe` execution | admitted host instrument |
| Signing-key custody | SecretStore-backed host custody |
| Safe durable authorization evidence | evidence ledger / FountainStore adapter |
| Domain admission | estate domain admission |
| DNS mutation | infrastructure provider adapter |
| Certificate lifecycle | certificate authority boundary |
| Public listener/upstream mapping | edge binding |

No row inherits authority from another.

A successful upstream login is not a Fountain capability grant. A valid token permits evaluation; it does not transfer ownership of the host capability. DNS, certificates, Caddy, HTTP, MCP and MIDI2 are interfaces or witnesses and do not become authorization authority.

Unknown domains fail closed. There is no default/global authority fallback in a shared runtime.
