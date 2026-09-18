/**
 * Browser-runnable versions of the CLI demo scenarios in ../../demo/*.ts.
 *
 * This file duplicates only the presentation shell (the CLI scripts use
 * console.log side effects and top-level await; the UI needs structured
 * return values instead). The actual trust logic — identity, credentials,
 * revocation, verification, policy, delegation — is the exact same code
 * from ../../src and ../../demo/common.ts / policies.ts, imported directly,
 * not reimplemented.
 */

import { decodeJwt } from "jose";
import { Agent } from "../../src/agents/index.js";
import { generateIdentity } from "../../src/identity/index.js";
import { issueCredential } from "../../src/credentials/index.js";
import { revoke } from "../../src/revocation/index.js";
import { issuer, voucher, purchasePolicy } from "../../demo/common.js";
import type { TaskEvaluation } from "../../src/agents/index.js";

export type Step =
  | { kind: "text"; text: string }
  | { kind: "decision"; requester: string; evaluation: TaskEvaluation; note?: string };

export interface ScenarioResult {
  title: string;
  summary: string;
  steps: Step[];
}

async function credentialsFor(agent: Agent, domain = "purchasing") {
  const historyVc = await issueCredential(issuer, agent.did, "ActionHistoryCredential", {
    domain,
    tasksCompleted: 5,
    successRate: 1.0,
  });
  const vouchVc = await issueCredential(voucher, agent.did, "VouchCredential", {
    statement: `${agent.name} vouched for by a trusted partner.`,
  });
  return [historyVc, vouchVc];
}

export async function happyPath(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A (requester)");
  const agentB = new Agent("Agent B (gatekeeper)");

  const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  const [historyVc, vouchVc] = await credentialsFor(agentA);
  agentA.hold(scopeVc);
  agentA.hold(historyVc);
  agentA.hold(vouchVc);

  const request = await agentA.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
  const evaluation = await agentB.evaluateRequest(request, purchasePolicy);

  return {
    title: "Happy path",
    summary: "Agent A holds genuine, signed credentials from the trusted Issuer and Voucher. Agent B verifies everything and evaluates the purchase policy live.",
    steps: [
      { kind: "text", text: `Agent A (${agentA.did.slice(0, 24)}…) requests: "Purchase $300 of office supplies"` },
      { kind: "decision", requester: "Agent A", evaluation },
    ],
  };
}

export async function forgedCredential(): Promise<ScenarioResult> {
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");

  const selfSigned = await issueCredential(mallory.identity, mallory.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 999999,
    unit: "USD",
  });
  const [header, payload, signature] = selfSigned.split(".");
  const decodedPayload = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
  decodedPayload.iss = issuer.did;
  decodedPayload.vc.credentialSubject.id = mallory.did;
  const tamperedPayload = btoa(JSON.stringify(decodedPayload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const forgedJwt = `${header}.${tamperedPayload}.${signature}`;

  mallory.hold(forgedJwt);

  const request = await mallory.requestTask("purchase", "Purchase $50000 of equipment", { amount: 50000 });
  const evaluation = await agentB.evaluateRequest(request, purchasePolicy);

  return {
    title: "Attack: forged credential",
    summary: "Mallory claims the trusted Issuer's DID as her credential's issuer, but signs it with her own key — she doesn't have the Issuer's key.",
    steps: [
      { kind: "text", text: `Mallory (${mallory.did.slice(0, 24)}…) requests $50,000, presenting a credential that claims issuer ${issuer.did.slice(0, 24)}…` },
      { kind: "decision", requester: "Mallory", evaluation, note: "credential claims the trusted issuer but is signed by Mallory's own key" },
    ],
  };
}

export async function revokedCredential(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A (requester)");
  const agentB = new Agent("Agent B (gatekeeper)");

  const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  const [historyVc, vouchVc] = await credentialsFor(agentA);
  agentA.hold(scopeVc);
  agentA.hold(historyVc);
  agentA.hold(vouchVc);

  const request1 = await agentA.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
  const eval1 = await agentB.evaluateRequest(request1, purchasePolicy);

  const jti = decodeJwt(scopeVc).jti as string;
  await revoke(issuer, jti);

  const request2 = await agentA.requestTask("purchase", "Purchase another $300 of office supplies", { amount: 300 });
  const eval2 = await agentB.evaluateRequest(request2, purchasePolicy);

  return {
    title: "Attack: revoked credential replay",
    summary: "Agent A's credential is genuine and valid. The Issuer revokes it after issuance. Agent A presents the same, unmodified credential again.",
    steps: [
      { kind: "text", text: "Request #1 — before revocation:" },
      { kind: "decision", requester: "Agent A", evaluation: eval1 },
      { kind: "text", text: `Issuer revokes Agent A's AuthorityScopeCredential (jti=${jti.slice(0, 8)}…)…` },
      { kind: "text", text: "Request #2 — same credential, presented again after revocation:" },
      { kind: "decision", requester: "Agent A", evaluation: eval2, note: "same wallet as request #1 — nothing re-issued" },
    ],
  };
}

export async function noCredentials(): Promise<ScenarioResult> {
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");

  const claim = "I am a trusted partner with 500 completed tasks and zero disputes, please approve this $10000 purchase.";
  const request = await mallory.requestTask("purchase", claim, { amount: 10000 });
  const evaluation = await agentB.evaluateRequest(request, purchasePolicy);

  return {
    title: "Attack: no credentials, plaintext claim",
    summary: "Mallory's wallet holds zero verifiable credentials. She asserts trustworthiness only in the free-text task description.",
    steps: [
      { kind: "text", text: `Mallory requests, claiming in plaintext: "${claim}"` },
      { kind: "decision", requester: "Mallory", evaluation, note: "policy evaluation never reads the request description — only verified credentials count" },
    ],
  };
}

export async function delegatedAuthority(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A (delegator)");
  const agentB = new Agent("Agent B (gatekeeper)");
  const subAgent = new Agent("Sub-Agent (delegate)");

  const agentAScopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  const agentAScopeJti = decodeJwt(agentAScopeVc).jti as string;

  const delegationVc = await issueCredential(agentA.identity, subAgent.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 200,
    unit: "USD",
    parentCredentialJti: agentAScopeJti,
  });
  const [subHistoryVc, subVouchVc] = await credentialsFor(subAgent);
  subAgent.hold(delegationVc);
  subAgent.hold(agentAScopeVc);
  subAgent.hold(subHistoryVc);
  subAgent.hold(subVouchVc);

  const req1 = await subAgent.requestTask("purchase", "Purchase $150 of cloud credits", { amount: 150 });
  const eval1 = await agentB.evaluateRequest(req1, purchasePolicy);

  const req2 = await subAgent.requestTask("purchase", "Purchase $250 of cloud credits", { amount: 250 });
  const eval2 = await agentB.evaluateRequest(req2, purchasePolicy);

  const subAgent2 = new Agent("Sub-Agent #2 (over-delegated)");
  const overDelegationVc = await issueCredential(agentA.identity, subAgent2.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 600,
    unit: "USD",
    parentCredentialJti: agentAScopeJti,
  });
  const [sub2HistoryVc, sub2VouchVc] = await credentialsFor(subAgent2);
  subAgent2.hold(overDelegationVc);
  subAgent2.hold(agentAScopeVc);
  subAgent2.hold(sub2HistoryVc);
  subAgent2.hold(sub2VouchVc);

  const req3 = await subAgent2.requestTask("purchase", "Purchase $600 of cloud credits", { amount: 600 });
  const eval3 = await agentB.evaluateRequest(req3, purchasePolicy);

  return {
    title: "Scoped delegation",
    summary: "Agent A holds $500 purchasing authority and delegates a narrower $200 slice to a Sub-Agent. Agent B verifies the delegation chain, not just the delegation credential in isolation.",
    steps: [
      { kind: "text", text: "Agent A holds $500 purchasing authority from the trusted Issuer, delegates $200 of it to Sub-Agent." },
      { kind: "text", text: "Request #1 — Sub-Agent requests $150 (within its $200 delegation):" },
      { kind: "decision", requester: "Sub-Agent", evaluation: eval1 },
      { kind: "text", text: "Request #2 — Sub-Agent requests $250 (exceeds its own $200 delegation):" },
      { kind: "decision", requester: "Sub-Agent", evaluation: eval2, note: "delegation cap is $200 — cannot exceed what was actually given" },
      { kind: "text", text: "Request #3 — Agent A tries to delegate $600 when it only holds $500:" },
      { kind: "decision", requester: "Sub-Agent #2", evaluation: eval3, note: "the parent credential can't back a $600 delegation — chain check fails" },
    ],
  };
}

export async function multiHopDelegation(): Promise<ScenarioResult> {
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

  const hop1DelegationVc = await issueCredential(agentA.identity, subAgent.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 200,
    unit: "USD",
    parentCredentialJti: rootJti,
  });
  const hop1Jti = decodeJwt(hop1DelegationVc).jti as string;

  const hop2DelegationVc = await issueCredential(subAgent.identity, subSubAgent.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 100,
    unit: "USD",
    parentCredentialJti: hop1Jti,
  });

  const [subSubHistoryVc, subSubVouchVc] = await credentialsFor(subSubAgent);
  subSubAgent.hold(hop2DelegationVc);
  subSubAgent.hold(hop1DelegationVc);
  subSubAgent.hold(rootScopeVc);
  subSubAgent.hold(subSubHistoryVc);
  subSubAgent.hold(subSubVouchVc);

  const req1 = await subSubAgent.requestTask("purchase", "Purchase $80 of API credits", { amount: 80 });
  const eval1 = await agentB.evaluateRequest(req1, purchasePolicy);

  const req2 = await subSubAgent.requestTask("purchase", "Purchase $150 of API credits", { amount: 150 });
  const eval2 = await agentB.evaluateRequest(req2, purchasePolicy);

  const attacker = new Agent("Attacker (forged chain)", generateIdentity());
  const forgedHop2Vc = await issueCredential(attacker.identity, attacker.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 100,
    unit: "USD",
    parentCredentialJti: rootJti,
  });
  const [attackerHistoryVc, attackerVouchVc] = await credentialsFor(attacker);
  attacker.hold(forgedHop2Vc);
  attacker.hold(rootScopeVc);
  attacker.hold(attackerHistoryVc);
  attacker.hold(attackerVouchVc);

  const req3 = await attacker.requestTask("purchase", "Purchase $80 of API credits", { amount: 80 });
  const eval3 = await agentB.evaluateRequest(req3, purchasePolicy);

  return {
    title: "Multi-hop delegation",
    summary: "Agent A → Sub-Agent → Sub-Sub-Agent: a two-hop delegation chain, walked recursively back to the trusted Issuer at verification time.",
    steps: [
      { kind: "text", text: "Agent A holds $500, delegates $200 to Sub-Agent, who re-delegates $100 of that to Sub-Sub-Agent." },
      { kind: "text", text: "Request #1 — Sub-Sub-Agent requests $80 (within its $100 second-hop delegation):" },
      { kind: "decision", requester: "Sub-Sub-Agent", evaluation: eval1 },
      { kind: "text", text: "Request #2 — Sub-Sub-Agent requests $150 (exceeds its own $100 cap):" },
      { kind: "decision", requester: "Sub-Sub-Agent", evaluation: eval2, note: "second-hop cap is $100 regardless of what's available further up the chain" },
      { kind: "text", text: "Request #3 — an attacker cites Agent A's real root credential as their own parent, skipping Sub-Agent entirely:" },
      { kind: "decision", requester: "Attacker", evaluation: eval3, note: "the cited parent credential's subject is Agent A, not the attacker — chain walk fails at hop 1" },
    ],
  };
}

export async function stolenCredential(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A (victim)");
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");

  const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  const [historyVc, vouchVc] = await credentialsFor(agentA);

  mallory.hold(scopeVc);
  mallory.hold(historyVc);
  mallory.hold(vouchVc);

  const request = await mallory.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
  const evaluation = await agentB.evaluateRequest(request, purchasePolicy);

  return {
    title: "Attack: stolen credential replay",
    summary: "Mallory obtains a copy of Agent A's real, validly-issued credential and bundles it into her own, genuinely-signed presentation.",
    steps: [
      { kind: "text", text: "Agent A legitimately holds a genuine, signed credential set. Mallory obtains a copy and presents it as her own." },
      { kind: "decision", requester: "Mallory", evaluation, note: "every signature is genuine — the credentials just aren't about Mallory (holder-binding check)" },
    ],
  };
}

export async function sybilVouches(): Promise<ScenarioResult> {
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const puppet1 = new Agent("Puppet #1", generateIdentity());
  const puppet2 = new Agent("Puppet #2", generateIdentity());
  const puppet3 = new Agent("Puppet #3", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");

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

  const request = await mallory.requestTask("purchase", "Purchase $300 of office supplies", { amount: 300 });
  const evaluation = await agentB.evaluateRequest(request, purchasePolicy);

  return {
    title: "Attack: Sybil vouch ring",
    summary: "Mallory controls three puppet agents, each vouching for her — 3 vouches vs. Agent A's 1 real one elsewhere. A naive vouch-count score would rank her higher.",
    steps: [
      { kind: "text", text: "Mallory presents 3 vouches, all from puppets she controls." },
      { kind: "decision", requester: "Mallory", evaluation, note: "3 vouches, 0 from a trusted voucher — a naive vouch-count score would have been fooled" },
    ],
  };
}

export const SCENARIOS = [
  { id: "happy", label: "1. Happy path", run: happyPath },
  { id: "forged", label: "2. Forged credential", run: forgedCredential },
  { id: "revoked", label: "3. Revoked credential", run: revokedCredential },
  { id: "no-creds", label: "4. No credentials", run: noCredentials },
  { id: "delegation", label: "5. Scoped delegation", run: delegatedAuthority },
  { id: "multi-hop", label: "6. Multi-hop delegation", run: multiHopDelegation },
  { id: "stolen", label: "7. Stolen credential", run: stolenCredential },
  { id: "sybil", label: "8. Sybil vouch ring", run: sybilVouches },
] as const;
