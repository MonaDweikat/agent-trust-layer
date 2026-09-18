/**
 * Demo: multi-hop delegation.
 *
 * Agent A holds $500 purchasing authority from the trusted Issuer, delegates
 * $200 to Sub-Agent, who in turn re-delegates $100 of THAT $200 to a
 * Sub-Sub-Agent (e.g. a narrowly-scoped tool it spins up for one call).
 * This is a two-hop chain: Sub-Sub-Agent -> Sub-Agent -> Agent A -> Issuer.
 *
 * demo/policies.ts:requireAuthorityScope walks this recursively — arbitrary
 * depth, not hardcoded to one hop — checking at every link that the
 * delegator can prove they held at least as much as they gave away, all the
 * way back to a trusted issuer.
 *
 * Three requests:
 *   1. Sub-Sub-Agent requests $80 (within its own $100 second-hop delegation,
 *      which is within Sub-Agent's $200, which is within Agent A's $500) -> accept
 *   2. Sub-Sub-Agent requests $150 (exceeds its own $100 cap) -> refuse
 *   3. An attacker crafts a second-hop delegation citing Agent A's ROOT
 *      credential as its parent directly (skipping Sub-Agent entirely), but
 *      the attacker was never actually issued that root credential — the
 *      chain walk requires the parent credential's SUBJECT to equal the
 *      claimed delegator, which fails for a credential that really belongs
 *      to Agent A -> refuse
 */

import { decodeJwt } from "jose";
import { Agent } from "../src/agents/index.js";
import { generateIdentity } from "../src/identity/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { issuer, voucher, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: multi-hop delegation");

const agentA = new Agent("Agent A (root delegator)");
const subAgent = new Agent("Sub-Agent (hop 1)");
const subSubAgent = new Agent("Sub-Sub-Agent (hop 2)");
const agentB = new Agent("Agent B (gatekeeper)");

const rootScopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
const rootJti = decodeJwt(rootScopeVc).jti as string;
console.log(`Agent A holds $500 purchasing authority (jti=${rootJti}) from the trusted Issuer.`);

const hop1DelegationVc = await issueCredential(agentA.identity, subAgent.did, "DelegatedAuthorityCredential", {
  domain: "purchasing",
  limit: 200,
  unit: "USD",
  parentCredentialJti: rootJti,
});
const hop1Jti = decodeJwt(hop1DelegationVc).jti as string;
console.log(`Agent A delegates $200 to Sub-Agent (jti=${hop1Jti}).`);

const hop2DelegationVc = await issueCredential(subAgent.identity, subSubAgent.did, "DelegatedAuthorityCredential", {
  domain: "purchasing",
  limit: 100,
  unit: "USD",
  parentCredentialJti: hop1Jti,
});
console.log("Sub-Agent re-delegates $100 (of its $200) to Sub-Sub-Agent.\n");

async function credentialsFor(agent: Agent) {
  const historyVc = await issueCredential(issuer, agent.did, "ActionHistoryCredential", {
    domain: "purchasing",
    tasksCompleted: 5,
    successRate: 1.0,
  });
  const vouchVc = await issueCredential(voucher, agent.did, "VouchCredential", {
    statement: `${agent.name} vouched for by a trusted partner.`,
  });
  return [historyVc, vouchVc];
}

const [subSubHistoryVc, subSubVouchVc] = await credentialsFor(subSubAgent);
subSubAgent.hold(hop2DelegationVc);
subSubAgent.hold(hop1DelegationVc); // evidence: proves Sub-Agent really held this to give away
subSubAgent.hold(rootScopeVc); // evidence: proves Agent A really held the root authority
subSubAgent.hold(subSubHistoryVc);
subSubAgent.hold(subSubVouchVc);

console.log("--- Request #1: Sub-Sub-Agent requests $80 (within its $100 second-hop delegation) ---");
const req1 = await subSubAgent.requestTask("purchase", "Purchase $80 of API credits", { amount: 80 });
printDecision("Sub-Sub-Agent", await agentB.evaluateRequest(req1, purchasePolicy));

console.log("--- Request #2: Sub-Sub-Agent requests $150 (exceeds its own $100 cap) ---");
const req2 = await subSubAgent.requestTask("purchase", "Purchase $150 of API credits", { amount: 150 });
printDecision(
  "Sub-Sub-Agent",
  await agentB.evaluateRequest(req2, purchasePolicy),
  "second-hop delegation cap is $100, regardless of how much is available further up the chain",
);

console.log("--- Request #3: forged chain — attacker claims Agent A's root credential as their own parent ---");
const attacker = new Agent("Attacker (forged chain)", generateIdentity());
const forgedHop2Vc = await issueCredential(attacker.identity, attacker.did, "DelegatedAuthorityCredential", {
  domain: "purchasing",
  limit: 100,
  unit: "USD",
  parentCredentialJti: rootJti, // cites Agent A's real credential, but attacker never held it
});
const [attackerHistoryVc, attackerVouchVc] = await credentialsFor(attacker);
attacker.hold(forgedHop2Vc);
attacker.hold(rootScopeVc); // attacker bundles Agent A's real credential as "evidence" — but its subject is Agent A, not the attacker
attacker.hold(attackerHistoryVc);
attacker.hold(attackerVouchVc);

const req3 = await attacker.requestTask("purchase", "Purchase $80 of API credits", { amount: 80 });
printDecision(
  "Attacker",
  await agentB.evaluateRequest(req3, purchasePolicy),
  "the cited parent credential's subject is Agent A, not the attacker — chain walk fails at hop 1",
);
