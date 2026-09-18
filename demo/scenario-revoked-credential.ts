/**
 * Demo: attack #2 — a genuinely-issued credential is later revoked, but
 * still presented.
 *
 * Agent A first requests a task successfully with a real, signed,
 * unexpired credential (accepted). The Issuer then revokes that exact
 * credential (e.g. after discovering Agent A misbehaved elsewhere). Agent A
 * presents the SAME credential again for a second task. Agent B re-checks
 * revocation status fresh on every request, so the second request is
 * refused even though signature and expiry both still pass — trust here is
 * a live property, not a one-time grant from issuance time.
 */

import { decodeJwt } from "jose";
import { Agent } from "../src/agents/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { revoke } from "../src/revocation/index.js";
import { issuer, voucher, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: revoked credential");

const agentA = new Agent("Agent A (requester)");
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

agentA.hold(scopeVc);
agentA.hold(historyVc);
agentA.hold(vouchVc);

console.log("--- Request #1: before revocation ---");
const request1 = await agentA.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
printDecision("Agent A", await agentB.evaluateRequest(request1, purchasePolicy));

console.log(`Issuer revokes Agent A's AuthorityScopeCredential (jti=${decodeJwt(scopeVc).jti})...\n`);
await revoke(issuer, decodeJwt(scopeVc).jti as string);

console.log("--- Request #2: same credential, presented again after revocation ---");
const request2 = await agentA.requestTask("purchase", "Purchase another $300 of office supplies", { amount: 300 });
printDecision("Agent A", await agentB.evaluateRequest(request2, purchasePolicy), "same wallet as request #1 — nothing re-issued");
