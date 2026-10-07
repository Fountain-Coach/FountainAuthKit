# Signing-key lifecycle

The admitted lifecycle is generate -> activate -> publish public material -> sign -> rotate -> retire -> compromise response -> recover.

The current SecretStore adapter implements custody and additive rotation with verification overlap. Explicit retirement/compromise recovery policy is not yet a complete production lifecycle and remains part of the first-release blocker set.
