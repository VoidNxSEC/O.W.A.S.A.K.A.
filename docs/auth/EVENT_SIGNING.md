# Event Signing

Every NetworkEvent leaving the OWASAKA pipeline carries an Ed25519
signature over its canonical bytes plus the key id that produced it,
so Spectre/Cerebro can verify origin independently. This is the
ADR-0062 layer of cryptographic provenance; the [Transparency
Log](TRANSPARENCY_LOG.md) builds on top of it.

For architectural rationale, threat model, and compliance cross-
reference see [ADR-0062][adr] in the ledger.

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0062.md

---

## At a glance

```
producer (OWASAKA pipeline)              consumer (Spectre / Cerebro / auditor)
─────────────────────────                ──────────────────────────────────────
PushNetworkEvent(e)                      JWKS fetch:
  e.Signature = nil                        GET /.well-known/jwks.json
  e.SignerKeyID = nil                      → keys[purpose=event-signing]
  canonical = JSON(e)
  e.Signature = Ed25519.Sign(            Verify on receive:
                  key.private,             canonical = JSON(e \ {sig, kid})
                  canonical)               key = jwks.find(e.kid)
  e.SignerKeyID = key.id                   ok = Ed25519.Verify(
  publish (BoltDB + NATS)                       key.public, canonical, e.sig)
```

The producer rotates keys every 24h with a 1h overlap window
(ADR-0059 cadence); the consumer pins the JWKS endpoint and accepts
both `active` and `rotating` keys. Retired keys fail verification.

---

## NetworkEvent schema

`internal/models/event.go`:

```go
type NetworkEvent struct {
    ID          string
    Type        EventType
    Source      string
    Destination string
    Metadata    map[string]any
    Timestamp   time.Time

    // Provenance (ADR-0062):
    Signature   []byte `json:"sig,omitempty"`
    SignerKeyID string `json:"kid,omitempty"`
}
```

Both signature fields are `omitempty` so unsigned events round-trip
through JSON cleanly. Production consumers REJECT unsigned events;
staging and dev tolerate them.

`NetworkEvent.CanonicalBytes()` returns the deterministic signing
surface: `json.Marshal(event_with_signature_fields_zeroed)`. Go's
`encoding/json` emits keys in struct field order and stable-sorts map
keys since Go 1.12 — enough determinism for OWASAKA's single-producer
model. RFC 8785 JCS hardening is a future Sprint 7 supply-chain item
once heterogeneous consumers exist.

---

## Signer / Verifier

`internal/events/signer.go`:

```go
authority := pki.NewAuthority(keystore)
_, _ = authority.GenerateKeyPair(ctx, pki.PurposeEventSigning, 24*time.Hour)

signer := events.NewSigner(authority)
signer.Sign(ctx, &event) // mutates event.Signature + event.SignerKeyID
```

Wired into `events.Pipeline.SetSigner(...)`. Every event passing
through `PushNetworkEvent` is signed BEFORE BoltDB persistence and
NATS publish — tampering anywhere downstream invalidates the
signature.

`internal/events/verifier.go`:

```go
verifier := events.NewVerifier(authority)
err := verifier.Verify(ctx, event)
// err is one of:
//   ErrSignatureMissing  — unsigned event
//   ErrSignatureInvalid  — bytes don't match the signature
//   ErrSignerKeyUnknown  — kid not in our PKI (includes cross-
//                          purpose: JWT kid presented for an event)
//   ErrSignerKeyRetired  — kid retired; no longer verifyable
//   nil                  — valid
```

`SignerErrorIs(err)` returns a short category string for audit logs.

---

## JWKS

`/.well-known/jwks.json` publishes both JWT-signing and event-signing
keys. Consumers disambiguate via the `owasaka_purpose` extension
field:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x":   "<base64url public key>",
      "use": "sig",
      "alg": "EdDSA",
      "kid": "<uuid>",
      "owasaka_purpose": "event-signing"
    },
    {
      "kty": "OKP", "crv": "Ed25519",
      ...
      "owasaka_purpose": "jwt-signing"
    }
  ]
}
```

Standard OIDC / JWKS consumers ignore the extension. OWASAKA-aware
consumers (Spectre, Cerebro) filter on it.

---

## Key rotation

Per the Sprint 1 [OPERATIONS runbook](OPERATIONS.md):

- Rotate `PurposeEventSigning` every 24h with `authority.Rotate(...)`.
- The previous key transitions to `rotating` for a 1h overlap window
  during which it verifies historical events but does not sign new
  ones. After the overlap, call `authority.Retire(...)`.
- The JWKS endpoint reflects the change immediately; consumers refresh
  on their normal cadence (typically every 60s) per the
  `Cache-Control: max-age=60` header.

A compromised key requires immediate retirement: `authority.Retire(kid)`.
Every event bearing that `kid` then fails verification — by design.

---

## Performance

Measured on commodity hardware (single core, Ed25519 native):

| Operation                     | Latency |
|-------------------------------|---------|
| Sign (Pipeline path)          | ~25 µs  |
| Verify (consumer path)        | ~80 µs  |
| Canonical bytes (single event)| ~5 µs   |

At 10k events/sec the signer costs ~250 ms CPU per wall second on one
core. Acceptable. If the event rate grows past one core, the signer
parallelizes trivially — there is no shared mutable state inside
`Signer.Sign`.

---

## Troubleshooting

| Symptom                                        | Likely cause                                                                                  |
|------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `ErrSignatureMissing` from a known producer    | Producer's `Signer` is nil (dev/test mode). Wire `Pipeline.SetSigner(...)` at bootstrap.       |
| `ErrSignerKeyUnknown` on a fresh deployment    | Consumer hasn't fetched the JWKS yet, or the kid is a JWT-signing key (wrong purpose).         |
| `ErrSignerKeyRetired` on historical events     | The rotation overlap window expired. Retain retired key public material for forensic replay only — not for live verification. |
| `ErrSignatureInvalid` after a binary upgrade   | Canonical-bytes shape drifted (struct field added/reordered). Re-publish events from the new binary; old events remain verifyable with the old binary's logic. |
| Sign latency spikes over 100 µs                | CPU contention. Profile; if real, batch signing via Sprint 7 hardening lands here.            |

---

## See also

- [TRANSPARENCY_LOG.md](TRANSPARENCY_LOG.md) — Merkle log that consumes signed events
- [OPERATIONS.md](OPERATIONS.md) — provisioning, rotation, revocation
- [MODEL.md](MODEL.md) — authentication architecture
- [ADR-0062][adr] — design rationale
- [ADR-0059](https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0059.md) — identity / PKI foundation
