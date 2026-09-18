# Architecture snapshot: identity → claims → verification → policy

```
┌─────────────┐      issues       ┌──────────────────────┐
│   Issuer    │ ────────────────▶ │  Verifiable Credential │
│ (did:key)   │   signs VC-JWT    │  (VC-JWT, Ed25519 sig) │
└─────────────┘                   └──────────┬───────────┘
                                              │ held by
                                              ▼
                                       ┌─────────────┐
                                       │   Agent A   │
                                       │  (did:key)  │
                                       │   wallet    │
                                       └──────┬──────┘
                                              │ presents VP
                                              │ (bundle of VC-JWTs)
                                              ▼
┌──────────────────────────────────────────────────────────┐
│                        Agent B (gatekeeper)                │
│                                                              │
│  1. VERIFICATION                                            │
│     - resolve issuer/subject did:key → public key            │
│     - check JWT signature                                    │
│     - check expiry                                            │
│     - check revocation status (Issuer's status registry)      │
│     → VerificationResult[] (each with a reason, not just bool)│
│                                                              │
│  2. POLICY                                                   │
│     - task type selects a rule set (not a single score)      │
│     - each rule checked against verified claims only          │
│     → { decision: accept | refuse, trace: RuleResult[] }      │
└──────────────────────────────────────────────────────────┘
```

## Design decisions

- **did:key over a hosted DID method**: self-certifying, resolvable offline,
  no registry to stand up for a demo — while still being a real W3C standard.
- **VC-JWT over JSON-LD/LD-Proofs**: gets real asymmetric signing/verification
  without the complexity of JSON-LD canonicalization and signature suites.
- **No trust score**: policy evaluation is a rule trace over verified claims.
  A single scalar "score" can't explain *why* a decision was made in 90
  seconds, and it collapses distinct kinds of trust (capability vs. history
  vs. social vouching) into one number that hides the failure mode. It's
  also gameable by volume — see the Sybil vouch-ring attack in
  [FAILURE-TEST.md](./FAILURE-TEST.md).
- **Revocation checked on every request**, not cached at issuance — trust is
  a live property, not a one-time grant.
- **Policy only ever reads verified claims** — anything a counterparty
  asserts about itself in plaintext (outside a signed credential) is
  structurally invisible to the policy engine.
- **Holder binding, not just signature validity**: a genuine signature only
  proves a credential's issuer really said it. Policy rules separately check
  `credential.subject === presenter DID` (on by default in
  `requireCredential`/`requireVouches`) so a copy of someone else's valid
  credential can't be replayed as your own — see the stolen-credential
  attack.
- **Scoped delegation as a first-class credential, not a special case**: a
  `DelegatedAuthorityCredential` references its parent credential by `jti`.
  The policy rule that checks authority
  (`demo/policies.ts:requireAuthorityScope`) walks this chain of custody
  **recursively, at arbitrary depth**: each link must be held by the agent
  claiming it, must not exceed what its own parent covers, and the walk only
  succeeds if it bottoms out at a real `AuthorityScopeCredential` from a
  trusted issuer. A delegator can never hand out more than they can prove
  they hold — at any point in the chain, not just at the root. `demo:multi-hop`
  exercises this at depth 2 (Issuer → Agent A → Sub-Agent → Sub-Sub-Agent),
  including a forged-parent-reference case the recursive subject check
  catches at the first hop it's checked.
