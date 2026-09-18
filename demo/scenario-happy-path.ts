/**
 * Demo: happy path.
 *
 * Agent A holds a genuine, signed AuthorityScopeCredential and
 * ActionHistoryCredential from the trusted Issuer, plus a VouchCredential
 * from a trusted Voucher. It requests a $300 "purchase" task from Agent B
 * (the gatekeeper), presenting all three as a signed Verifiable Presentation.
 * Agent B verifies everything and evaluates the purchase policy live.
 */

import { Agent } from "../src/agents/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { issuer, voucher, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: happy path");

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

console.log(`Agent A (${agentA.did}) requests: "Purchase $300 of office supplies"`);
const request = await agentA.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });

const decision = await agentB.evaluateRequest(request, purchasePolicy);
printDecision("Agent A", decision);
