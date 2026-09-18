# Two-year thesis: agent identity and reputation

Agent identity will converge on self-certifying keys, not centrally-issued
accounts. Agents are provisioned and retired at a rate no registrar can gate
— a task-scoped sub-agent might live for minutes — so identity has to be
something an agent can mint for itself and prove control of, the way
`did:key` does here, not something a platform hands out.

Reputation stops being a portable score and becomes a portfolio of scoped,
expiring, revocable credentials, each issued by whoever actually observed the
behavior — a marketplace, a counterparty agent, a human — rather than a
platform-wide oracle. A score compresses distinct kinds of trust (capability,
history, vouching) into one number and is gameable by volume, as this
project's Sybil vouch-ring attack shows: three self-issued vouches outrank
one real one under any counting scheme, but not under one that only trusts
specific issuers. Reputation's unit becomes "trusted by whom, for what,
until when," not "trusted, how much."

Authority delegation chains become the norm. A human grants a scoped
credential to their agent, which sub-delegates a narrower slice to a
helper, which sub-delegates again, each link independently verifiable and
revocable, and each delegator constrained to hand out no more than it
actually holds — this project's recursive, arbitrary-depth chain (closer to
UCAN/ZCAP-LD capability delegation than to flat VCs) is a minimal instance
of what has to hold once agents routinely spawn agents that spawn agents.

The open question deciding who wins this layer: whether verification
infrastructure — issuers, status registries, policy languages — stays
federated and standards-based, letting agents from different vendors verify
each other without a shared platform, or consolidates around one or two
platform-owned reputation graphs, as app-store identity did for mobile.
Agent commerce likely resists that longer, since the counterparties
transacting are themselves economic actors incentivized to shop across
platforms.
