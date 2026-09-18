/**
 * Demo: attack #5 — Sybil vouch ring (defeated by a trusted-voucher allowlist).
 *
 * Mallory spins up three puppet agents she fully controls and has each of
 * them issue her a VouchCredential. On a naive "reputation score" system —
 * count the vouches — Mallory would now look MORE trustworthy than Agent A
 * from the earlier scenarios, who has exactly one real vouch. This is
 * exactly the spam/fraud collapse the brief warns multi-agent systems fall
 * into without real trust primitives.
 *
 * The policy's requireVouches rule doesn't count vouches — it counts vouches
 * from a fixed, independently-trusted set of vouchers (TRUSTED_VOUCHERS).
 * Puppets Mallory controls aren't on that list, so three self-serving
 * vouches contribute exactly as much as zero.
 */

import { Agent } from "../src/agents/index.js";
import { generateIdentity } from "../src/identity/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { issuer, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: Sybil vouch ring");

const mallory = new Agent("Mallory (attacker)", generateIdentity());
const puppet1 = new Agent("Puppet #1 (Mallory-controlled)", generateIdentity());
const puppet2 = new Agent("Puppet #2 (Mallory-controlled)", generateIdentity());
const puppet3 = new Agent("Puppet #3 (Mallory-controlled)", generateIdentity());
const agentB = new Agent("Agent B (gatekeeper)");

// Mallory does hold genuine scope + history credentials from the real
// issuer, isolating this scenario to the vouch rule specifically.
const scopeVc = await issueCredential(issuer, mallory.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
const historyVc = await issueCredential(issuer, mallory.did, "ActionHistoryCredential", {
  domain: "purchasing",
  tasksCompleted: 42,
  successRate: 0.95,
});

const puppetVouches = await Promise.all(
  [puppet1, puppet2, puppet3].map((puppet) =>
    issueCredential(puppet.identity, mallory.did, "VouchCredential", {
      statement: `${puppet.name} vouches for Mallory (self-serving).`,
    }),
  ),
);

mallory.hold(scopeVc);
mallory.hold(historyVc);
for (const v of puppetVouches) mallory.hold(v);

console.log(`Mallory presents 3 vouches (from puppets she controls) vs. Agent A's 1 real vouch elsewhere.\n`);

const request = await mallory.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
const decision = await agentB.evaluateRequest(request, purchasePolicy);
printDecision(
  "Mallory",
  decision,
  "3 vouches, 0 of them from a trusted voucher — a naive vouch-count score would have been fooled",
);
