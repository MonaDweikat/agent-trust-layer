# Agent Trust Layer

A trust, credential, and scoped-authority layer for AI agents: identity via
`did:key`, claims via Verifiable Credentials (VC-JWT), verification, and a
policy engine that gates task acceptance — plus scoped, multi-hop authority
delegation and a set of concrete attacks the trust layer is built to catch.

Status: fully implemented and working end to end (identity, credentials,
revocation, verification, policy, delegation, agents, 8 demo scenarios).

**Live demo:** https://monadweikat.github.io/agent-trust-layer/ — runs the
identical logic client-side in your browser (real key generation, real
signing, real verification), no backend involved.

## Setup
```
npm install
npm test        # runs all module-level tests (identity, credentials, revocation, verification, policy)
npm run demo:all
```

Or run scenarios individually:
```
npm run demo:happy       # Agent A's credentials verify; Agent B accepts the task
npm run demo:forged      # forged issuer signature — refused
npm run demo:revoked     # valid credential, revoked after issuance, re-checked live — refused
npm run demo:no-creds    # plaintext trust claim, zero credentials — refused
npm run demo:delegation  # Agent A delegates scoped $ authority to a sub-agent — chain verified
npm run demo:multi-hop   # a 2-hop delegation chain, plus a forged-parent-reference attack — caught mid-chain
npm run demo:stolen      # Mallory replays a copy of Agent A's real credential — caught by holder binding
npm run demo:sybil       # Mallory's 3 puppet-agent vouches don't count — untrusted vouchers
```

To run the browser demo locally instead of the hosted version:
```
npm run web:dev
```

## Docs
- [PLAN.md](./PLAN.md) — build order, design fixes, and out-of-scope decisions (with reasoning)
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) — identity → claims → verification → policy, and the key design decisions
- [docs/FAILURE-TEST.md](./docs/FAILURE-TEST.md) — 6 attack scenarios and what specifically catches each
- [docs/THESIS.md](./docs/THESIS.md) — two-year thesis on agent identity/reputation (300 words)

## What's real here (not vibes)
- Ed25519 keypairs, `did:key` DIDs (W3C standard, self-certifying, resolvable offline)
- Actual signed JWTs (EdDSA) for every credential and presentation, verified with `jose`
- A signed revocation registry, re-checked on every request (not cached from issuance)
- Holder binding: a genuine credential about someone else doesn't count toward you, even with valid signatures throughout
- A delegation chain of **arbitrary depth**, walked recursively, where a delegator can never hand out more authority than they can prove they hold — checked at every hop, not assumed at the root

## Notes

### What to look at
If you only have a few minutes, in order:

1. **Live demo → "6. Multi-hop delegation"** at https://monadweikat.github.io/agent-trust-layer/
   — watch the timeline: two real delegation hops, then a forged-chain attack
   caught mid-verification. This single scenario shows identity, credentials,
   verification, and policy all in one interaction.
2. **`demo/policies.ts`** (`isValidAuthorityCredential`) — the recursive
   chain-of-custody walk: a delegator can never hand out more authority than
   they can prove they hold, checked at every hop back to a trusted issuer.
   This is the technical centerpiece.
3. **`src/policy/index.ts`** — the whole rule engine, and why `evaluate()`
   returns a trace instead of a score. Read alongside the Sybil vouch-ring
   attack (`demo:sybil`) to see why that distinction isn't cosmetic.
4. **`docs/FAILURE-TEST.md`** — 6 attacks, each defeated by a different
   layer (signing, lifecycle, holder identity, chain-of-custody, social
   graph). Worth reading even without running the code.
5. **`src/verification/index.ts`** — every rejection returns a specific,
   human-readable reason rather than a boolean; this is what makes each
   demo decision explainable, not just correct.

### AI tools used
Built with Claude Code (Anthropic). Used for scaffolding, implementation of
all modules, and drafting the attack scenarios and docs. All cryptographic
logic (signing/verification/did:key encoding) was written and independently
smoke-tested against expected pass/fail cases rather than assumed correct.

### Key decisions
- **`did:key` over a hosted DID method** — self-certifying, resolvable
  offline, no registry dependency, while still a real W3C standard.
- **VC-JWT over JSON-LD/LD-Proofs** — real asymmetric signing/verification
  without JSON-LD canonicalization complexity.
- **No trust score, anywhere** — policy evaluation always produces a rule
  trace over verified claims, never a scalar. See the Sybil vouch-ring
  attack for why a score specifically fails here.
- **Holder binding by default** — a credential's signature being genuine
  doesn't mean it belongs to whoever is presenting it; policy rules check
  `credential.subject === presenter` separately. See the stolen-credential
  attack.
- **Delegation as a recursively-verified credential chain**, not a flat
  grant — a delegator can never hand out more authority than they can prove
  they hold, checked at every hop back to a trusted root.

Full reasoning for each: [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).

### Out of scope
See "Deliberately out of scope" in [PLAN.md](./PLAN.md) for the full
reasoning. In short: no hosted DID resolution (did:key stays offline and
dependency-free on purpose), no persistent revocation store (the in-memory
signed-list mechanism is already real; only its storage medium would
change), and no weighted/multi-party trust graphs (a weighted score is
exactly the anti-pattern this project argues against — see the Sybil
vouch-ring scenario). Multi-hop delegation chains, by contrast, are fully
implemented — see `demo:multi-hop`.
