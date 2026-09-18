/**
 * Demo: scoped delegation.
 *
 * Agent A holds $500 of purchasing authority from the trusted Issuer. It
 * delegates a narrower $200 slice to Sub-Agent (e.g. a tool-calling helper
 * it spins up for a specific job), by issuing Sub-Agent a
 * DelegatedAuthorityCredential that references Agent A's own credential
 * (`parentCredentialJti`).
 *
 * When Sub-Agent requests a task, it bundles BOTH the delegation credential
 * AND Agent A's original AuthorityScopeCredential as supporting evidence.
 * Agent B's policy (demo/policies.ts:requireAuthorityScope) walks the chain:
 * the delegation must be about the presenter, the parent must be a real
 * trusted-issued credential belonging to the delegator, and the parent's
 * limit must actually cover what was delegated — a delegator can't hand out
 * more authority than it holds.
 *
 * Three requests show the chain being checked, not assumed:
 *   1. Sub-Agent requests $150 (within its $200 delegation) -> accept
 *   2. Sub-Agent requests $250 (exceeds its own $200 delegation) -> refuse
 *   3. A second sub-agent is over-delegated $600 by an agent that only
 *      holds $500 -> refuse, because the parent credential can't cover it
 */

import { decodeJwt } from "jose";
import { Agent } from "../src/agents/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { issuer, voucher, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: scoped delegation of authority");

const agentA = new Agent("Agent A (delegator)");
const agentB = new Agent("Agent B (gatekeeper)");
const subAgent = new Agent("Sub-Agent (delegate)");

const agentAScopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
const agentAScopeJti = decodeJwt(agentAScopeVc).jti as string;

console.log(`Agent A holds $500 purchasing authority (jti=${agentAScopeJti}) from the trusted Issuer.`);
console.log("Agent A delegates $200 of it to Sub-Agent...\n");

const delegationVc = await issueCredential(agentA.identity, subAgent.did, "DelegatedAuthorityCredential", {
  domain: "purchasing",
  limit: 200,
  unit: "USD",
  parentCredentialJti: agentAScopeJti,
});

const subHistoryVc = await issueCredential(issuer, subAgent.did, "ActionHistoryCredential", {
  domain: "purchasing",
  tasksCompleted: 5,
  successRate: 1.0,
});
const subVouchVc = await issueCredential(voucher, subAgent.did, "VouchCredential", {
  statement: "Spun up by Agent A for a scoped procurement task.",
});

subAgent.hold(delegationVc);
subAgent.hold(agentAScopeVc); // evidence: proves the delegator actually held this authority
subAgent.hold(subHistoryVc);
subAgent.hold(subVouchVc);

console.log("--- Request #1: Sub-Agent requests $150 (within its $200 delegation) ---");
const req1 = await subAgent.requestTask("purchase", "Purchase $150 of cloud credits", { amount: 150 });
printDecision("Sub-Agent", await agentB.evaluateRequest(req1, purchasePolicy));

console.log("--- Request #2: Sub-Agent requests $250 (exceeds its own $200 delegation) ---");
const req2 = await subAgent.requestTask("purchase", "Purchase $250 of cloud credits", { amount: 250 });
printDecision("Sub-Agent", await agentB.evaluateRequest(req2, purchasePolicy), "delegation cap is $200 — the sub-agent cannot exceed what it was actually given");

console.log("--- Request #3: over-delegation — Agent A tries to delegate $600 when it only holds $500 ---");
const subAgent2 = new Agent("Sub-Agent #2 (over-delegated)");
const overDelegationVc = await issueCredential(agentA.identity, subAgent2.did, "DelegatedAuthorityCredential", {
  domain: "purchasing",
  limit: 600,
  unit: "USD",
  parentCredentialJti: agentAScopeJti,
});
const sub2HistoryVc = await issueCredential(issuer, subAgent2.did, "ActionHistoryCredential", {
  domain: "purchasing",
  tasksCompleted: 5,
  successRate: 1.0,
});
const sub2VouchVc = await issueCredential(voucher, subAgent2.did, "VouchCredential", {
  statement: "Spun up by Agent A for a scoped procurement task.",
});
subAgent2.hold(overDelegationVc);
subAgent2.hold(agentAScopeVc);
subAgent2.hold(sub2HistoryVc);
subAgent2.hold(sub2VouchVc);

const req3 = await subAgent2.requestTask("purchase", "Purchase $600 of cloud credits", { amount: 600 });
printDecision(
  "Sub-Agent #2",
  await agentB.evaluateRequest(req3, purchasePolicy),
  "Agent A only holds $500 — the parent credential can't back a $600 delegation, chain check fails",
);
