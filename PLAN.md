# Build plan and design log

Status: all modules below are implemented, tested, and passing.

1. **`src/identity`** — Ed25519 keygen + did:key derivation/resolution + sign/verify.
   Tested: two identities, sign/verify, tamper detection, wrong-key rejection,
   did:key round-trip (matches the real `z6Mk...` Ed25519 prefix).

2. **`src/credentials`** — VC-JWT issuance for four credential types
   (`ActionHistoryCredential`, `AuthorityScopeCredential`, `VouchCredential`,
   `DelegatedAuthorityCredential`), plus VP bundling. Tested: issue, decode,
   verify against issuer key, reject under wrong key.

3. **`src/revocation`** — signed status registry (revoke/isRevoked), keyed
   per issuer, re-verified on every read. Tested: revoke flips isRevoked,
   unrelated credentials unaffected.

4. **`src/verification`** — signature → expiry → revocation checks, each
   returning a specific reason string. Tested against valid, expired,
   forged, and revoked credentials, plus full presentation verification.

5. **`src/policy`** — declarative rule engine + `evaluate()` with a full
   trace, context-aware (`{ holderDid, task }`) so rules can check both
   identity binding and task-specific parameters (e.g. requested amount).
   Tested against accept/refuse/holder-binding-violation cases.

6. **`src/agents`** — `Agent` class tying identity + wallet +
   request/evaluate together; `TaskRequest` carries structured `params` (not
   just a free-text description) so policy rules can check real values.

7. **`demo/*.ts`** and **`web/`** — 8 scenarios: happy path plus 6 distinct
   attacks and a scoped-delegation walkthrough, runnable both as CLI scripts
   (`npm run demo:<name>` / `npm run demo:all`) and as an interactive
   browser demo (`npm run web:dev`) that runs the identical logic client-side.

## Two design fixes made while building delegation
- **Holder binding**: policy rules check `credential.subject === presenter`
  by default (`src/policy`'s `requireCredential`/`requireVouches`) — this
  closes the "replay someone else's valid credential" gap, demonstrated in
  `demo:stolen`.
- **Amount-aware policy**: authority checks compare against the task's
  actual requested amount (`EvaluationContext.task`), not a threshold fixed
  at policy-definition time — necessary once delegation needed to check
  varying requested amounts against varying granted scopes.

## Deliberately out of scope
- **Hosted/networked DID resolution** — did:key keeps verification fully
  offline and dependency-free. A networked DID method (did:web, a universal
  resolver) would trade a real, already-standards-based mechanism for a
  network dependency that adds fragility without improving conceptual
  clarity or technical depth.
- **Persistent (file/DB-backed) revocation registry** — the in-memory,
  signed-list mechanism is already real; only its storage medium would
  change. A hosted StatusList2021 endpoint is the natural real-world
  equivalent if this moved beyond a demo.
- **Multi-party consensus / weighted vouch graphs** — a weighted trust graph
  is a reputation *score* by another name. Scoring a counterparty by an
  aggregate number is exactly the pattern this project argues against (see
  the Sybil vouch-ring attack). The binary trusted-voucher allowlist is the
  intentional alternative, not a placeholder for a future score.

Multi-hop delegation chains, by contrast, are implemented rather than left
out: `demo/policies.ts`'s `requireAuthorityScope` recursively walks a
delegation chain of arbitrary depth back to a trusted root (`demo:multi-hop`).
