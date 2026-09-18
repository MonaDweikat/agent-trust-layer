/**
 * Demo: attack #4 — stolen credential replay (defeated by holder binding).
 *
 * Mallory somehow obtains a copy of Agent A's real, validly-issued,
 * unexpired, unrevoked AuthorityScopeCredential (e.g. intercepted in
 * transit, or leaked). She bundles it into her OWN Verifiable Presentation,
 * signed with her own key — that signature is genuine, she really does
 * control the DID presenting it.
 *
 * Signature checks all pass: the credential's issuer signature is real, and
 * Mallory's presentation signature over the bundle is real too. What fails
 * is holder binding — src/policy's requireCredential (and requireVouches)
 * check that `credential.subject === presenter DID` by default. The
 * credential is about Agent A, not Mallory, so it doesn't count toward
 * Mallory's request no matter how genuine the signatures are.
 *
 * This is why "verify the signature" is necessary but not sufficient: a
 * credential's authenticity and its ownership by the presenter are two
 * different questions.
 */

import { Agent } from "../src/agents/index.js";
import { generateIdentity } from "../src/identity/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { issuer, voucher, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: stolen credential replay");

const agentA = new Agent("Agent A (victim)");
const mallory = new Agent("Mallory (attacker)", generateIdentity());
const agentB = new Agent("Agent B (gatekeeper)");

const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
const historyVc = await issueCredential(issuer, agentA.did, "ActionHistoryCredential", {
  domain: "purchasing",
  tasksCompleted: 42,
  successRate: 0.95,
});
const vouchVc = await issueCredential(voucher, agentA.did, "VouchCredential", {
  statement: "Worked with this agent for 6 months, reliable.",
});

console.log(`Agent A (${agentA.did}) legitimately holds a genuine, signed credential set.`);
console.log(`Mallory (${mallory.did}) obtains a COPY of Agent A's credentials and presents them as her own.\n`);

// Mallory holds copies of Agent A's real credential JWTs, unmodified, but
// presents them in a VP signed with her own key.
mallory.hold(scopeVc);
mallory.hold(historyVc);
mallory.hold(vouchVc);

const request = await mallory.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
const decision = await agentB.evaluateRequest(request, purchasePolicy);
printDecision(
  "Mallory",
  decision,
  "every signature is genuine — the credentials just aren't about Mallory (holder-binding check)",
);
