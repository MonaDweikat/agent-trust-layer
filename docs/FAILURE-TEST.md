# Failure test: attack scenarios

Six concrete attacks, each hitting a different layer of the trust model,
implemented as separate demo scripts. Together they show the defense isn't
one check that could be bypassed once, but independent guarantees at
signing, lifecycle, identity-binding, chain-of-custody, and social-graph
layers.

## 1. Forged credential (`demo:forged`)
**Attack**: Mallory crafts a credential payload that *claims* to be issued by
the trusted Issuer (`iss` field set to the Issuer's DID) but signs it with her
own private key, because she doesn't have the Issuer's key.

**Caught by**: signature verification. Resolving the `iss` DID gives the
Issuer's real public key; the signature doesn't match it. Rejected before
policy evaluation ever runs.

## 2. Revoked credential still presented (`demo:revoked`)
**Attack**: Agent A holds a real, correctly-signed, unexpired credential. The
Issuer revokes it after issuance (e.g. following a dispute). Agent A presents
the same credential again.

**Caught by**: revocation check against the Issuer's signed status registry,
performed fresh on every request — not cached from a prior successful
verification.

## 3. Spoofed agent, no credentials (`demo:no-creds`)
**Attack**: Mallory sends a task request with a plaintext claim ("I've
completed 500 tasks, trust me") and no verifiable credential at all.

**Caught by**: structural separation between the request payload and the
policy engine's inputs — the policy engine only ever evaluates rules against
`VerificationResult`s that came out of the verification layer. A plaintext
field in the request body is never on that path, so there is nothing for the
attack to exploit; the rule requiring a credential simply has no evidence to
satisfy it.

## 4. Stolen credential replay (`demo:stolen`)
**Attack**: Mallory obtains a *copy* of Agent A's real, validly-issued,
unexpired, unrevoked credential (e.g. intercepted, leaked) and bundles it
into her own Verifiable Presentation, signed with her own genuine key.

**Caught by**: holder binding. Every signature involved is authentic — the
credential's issuer signature and Mallory's presentation signature both
verify. What fails is that policy rules check `credential.subject ===
presenter DID` by default (`src/policy`'s `requireCredential` /
`requireVouches`). The credential is about Agent A, not Mallory, so it
doesn't count toward her request. This demonstrates that "the signature is
valid" and "this credential belongs to whoever is presenting it" are two
different questions — a gap real VC deployments have gotten wrong.

## 5. Sybil vouch ring (`demo:sybil`)
**Attack**: Mallory spins up three puppet agents she fully controls and has
each vouch for her. A naive "count the vouches" reputation score would now
rank her above a legitimately-vouched agent with only one real vouch.

**Caught by**: the vouch rule doesn't count vouches — it counts vouches from
a fixed, independently-trusted allowlist of vouchers. Puppets Mallory
controls aren't on it, so three self-serving vouches contribute exactly as
much as zero. This is the concrete reason the trust model in this project is
a rule set over verified, attributed claims rather than a scalar score: a
score can be inflated by volume; a policy that only trusts specific issuers
cannot be.

## 6. Forged delegation-chain link (`demo:multi-hop`, request #3)
**Attack**: an attacker issues themselves a `DelegatedAuthorityCredential`
that cites Agent A's real `AuthorityScopeCredential` as its `parentCredentialJti`
— a genuine credential, correctly signed by the trusted Issuer — hoping to
borrow its legitimacy without ever having been delegated anything by Agent A.

**Caught by**: the recursive chain walk in `demo/policies.ts` requires the
cited parent credential's *subject* to equal the claimed delegator (the
attacker) at every hop, not just that the parent credential is real and
valid. Agent A's credential is about Agent A, so citing its jti while
claiming to be the delegator fails immediately — distinct from attack #1
(a forged issuer signature) because here every signature involved actually
is genuine; what's forged is the claim of a delegation relationship that
never happened.

## What this demonstrates
The six attacks target six different layers — issuer authenticity,
credential lifecycle, the plaintext/verified-claims boundary, holder
identity, chain-of-custody in delegation, and the social trust graph itself.
No single mechanism (e.g. "just check signatures") would have caught all
six; each layer closes a gap the others don't.
