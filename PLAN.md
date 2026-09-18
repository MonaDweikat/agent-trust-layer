# Build plan: The Agent That Earns Trust

Status: all steps below are implemented, tested, and passing.

1. **`src/identity`** ✅ — Ed25519 keygen + did:key derivation/resolution + sign/verify.
   Tested: two identities, sign/verify, tamper detection, wrong-key rejection,
   did:key round-trip (matches real `z6Mk...` Ed25519 prefix).

2. **`src/credentials`** ✅ — VC-JWT issuance for the three base credential types
   (`ActionHistoryCredential`, `AuthorityScopeCredential`, `VouchCredential`)
   plus a fourth added during hardening (`DelegatedAuthorityCredential`), and
   VP bundling. Tested: issue, decode, verify against issuer key, reject
   under wrong key.

3. **`src/revocation`** ✅ — signed status registry (revoke/isRevoked), keyed
   per issuer, re-verified on every read. Tested: revoke flips isRevoked,
   unrelated credentials unaffected.

4. **`src/verification`** ✅ — signature → expiry → revocation checks, each
   returning a specific reason string. Tested against valid, expired,
   forged, and revoked credentials, plus full presentation verification.

5. **`src/policy`** ✅ — declarative rule engine + `evaluate()` with a full
   trace, context-aware (`{ holderDid, task }`) so rules can check both
   identity binding and task-specific parameters (e.g. requested amount).
   Tested against accept/refuse/holder-binding-violation cases.

6. **`src/agents`** ✅ — `Agent` class tying identity + wallet +
   request/evaluate together; `TaskRequest` carries structured `params` (not
   just a free-text description) so policy rules can check real values.

7. **`demo/*.ts`** ✅ — 7 scenarios: happy path, forged credential, revoked
   credential, no credentials, scoped delegation, stolen credential replay,
   Sybil vouch ring. All runnable via `npm run demo:<name>` or `npm run demo:all`.

## Hardening pass (beyond the original 7 steps)
Two real gaps were found and closed while building the delegation scenario:
- **Holder binding**: policy rules now check `credential.subject === presenter`
  by default — closes the "replay someone else's valid credential" gap.
  See `demo:stolen`.
- **Amount-aware policy**: the purchase policy originally hardcoded a fixed
  `$300` threshold at policy-definition time, which broke once delegation
  needed to check varying requested amounts against varying granted scopes.
  Fixed by threading the task's actual parameters through
  `EvaluationContext` so rules check against the real request, not a
  constant.

## Still open before submission (non-code)
- Record the 90-second Loom (`npm run demo:all` covers all 7 scenarios; pick
  the 2-3 most legible for the time limit — happy path + delegation +
  one attack is a strong 90s arc)
- Decide the "live demo URL" format (this is a CLI; options: a short screen
  recording hosted somewhere, or a minimal web wrapper — flagged to the user)
- First git commit (nothing committed yet)

## Deliberately out of scope
Revisited explicitly, not just left over from the original scaffold:

- **Hosted/networked DID resolution** — did:key keeps verification fully
  offline and dependency-free. Swapping in a networked DID method (did:web,
  a universal resolver) would trade a real, already-standards-based
  mechanism for a network dependency that adds fragility to a live demo
  without improving any scored criterion.
- **Persistent (file/DB-backed) revocation registry** — considered and
  rejected: every demo scenario generates fresh random identities per run,
  so persisted revocation state would just accumulate orphaned entries
  nothing ever looks up again. It would be inert scaffolding, not a
  demonstrated capability. The in-memory, signed-list mechanism is already
  real; only its storage medium would change, and a hosted StatusList2021
  endpoint (the real-world equivalent) is the natural next step if this
  moved beyond a demo.
- **Multi-hop delegation** — reconsidered and IMPLEMENTED (`demo:multi-hop`):
  `demo/policies.ts:requireAuthorityScope` recursively walks a delegation
  chain of arbitrary depth back to a trusted root, not hardcoded to one hop.
- **Multi-party consensus / weighted vouch graphs** — deliberately still out.
  A weighted trust graph is a reputation *score* by another name, and
  scoring a counterparty by an aggregate number is exactly the pattern this
  project argues against (see the Sybil vouch-ring attack) and one of the
  brief's explicit disqualifiers. The binary trusted-voucher allowlist is
  the intentional alternative, not a placeholder for a future score.
