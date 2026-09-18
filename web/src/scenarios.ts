/**
 * Browser-runnable versions of the CLI demo scenarios in ../../demo/*.ts,
 * rebuilt to narrate the actual protocol between agents step by step
 * (request sent → presentation received → each credential checked → each
 * policy rule checked → decision) instead of only showing a final verdict.
 *
 * The trust logic itself — identity, credentials, revocation, verification,
 * policy — is the exact same code from ../../src, imported directly. This
 * file calls `verifyPresentation` and `evaluate` directly (rather than
 * through Agent.evaluateRequest) purely to expose the intermediate results
 * for the timeline UI; no logic is reimplemented.
 */

import { decodeJwt } from "jose";
import { Agent } from "../../src/agents/index.js";
import { generateIdentity } from "../../src/identity/index.js";
import { issueCredential } from "../../src/credentials/index.js";
import { revoke } from "../../src/revocation/index.js";
import { verifyPresentation, type VerifiedCredential } from "../../src/verification/index.js";
import { evaluate } from "../../src/policy/index.js";
import { issuer, voucher, purchasePolicy } from "../../demo/common.js";

export type Step =
  | { kind: "narrate"; text: string }
  | { kind: "issue"; from: string; to: string; label: string }
  | { kind: "message"; from: string; to: string; label: string }
  | { kind: "check"; actor: string; label: string; passed: boolean; detail?: string }
  | { kind: "decision"; requester: string; accepted: boolean };

export interface ScenarioResult {
  title: string;
  summary: string;
  steps: Step[];
}

const names = new Map<string, string>([
  [issuer.did, "Issuer"],
  [voucher.did, "Voucher"],
]);

function label(agent: Agent): string {
  if (!names.has(agent.did)) names.set(agent.did, agent.name);
  return agent.name;
}

function shortDid(did: string): string {
  return names.get(did) ?? `${did.slice(0, 16)}…`;
}

async function credentialsFor(agent: Agent, steps: Step[], domain = "purchasing") {
  const historyVc = await issueCredential(issuer, agent.did, "ActionHistoryCredential", {
    domain,
    tasksCompleted: 5,
    successRate: 1.0,
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(agent), label: "ActionHistoryCredential (successRate 1.0)" });

  const vouchVc = await issueCredential(voucher, agent.did, "VouchCredential", {
    statement: `${agent.name} vouched for by a trusted partner.`,
  });
  steps.push({ kind: "issue", from: "Voucher", to: label(agent), label: "VouchCredential" });

  return [historyVc, vouchVc];
}

/**
 * The core protocol, narrated: requester sends a task request bundling a
 * Verifiable Presentation; gatekeeper verifies the presentation's holder
 * signature, then each credential inside it, then evaluates the policy
 * against whatever verified — exactly what Agent.evaluateRequest does
 * internally, unrolled into visible steps.
 */
async function interact(
  requester: Agent,
  gatekeeper: Agent,
  description: string,
  amount: number,
): Promise<Step[]> {
  label(requester);
  label(gatekeeper);
  const steps: Step[] = [];

  const request = await requester.requestTask("purchase", description, { amount });
  steps.push({
    kind: "message",
    from: requester.name,
    to: gatekeeper.name,
    label: `Task request — "${description}" + signed Verifiable Presentation`,
  });

  const verification = await verifyPresentation(request.presentation);

  if (!verification.holderValid) {
    steps.push({
      kind: "check",
      actor: gatekeeper.name,
      label: "Presentation signature must verify against the holder's DID",
      passed: false,
      detail: verification.holderReason,
    });
    steps.push({ kind: "decision", requester: requester.name, accepted: false });
    return steps;
  }

  steps.push({
    kind: "check",
    actor: gatekeeper.name,
    label: `Presentation signature verified (holder: ${shortDid(verification.holderDid!)})`,
    passed: true,
  });

  for (const result of verification.credentials) {
    if (result.valid) {
      steps.push({
        kind: "check",
        actor: gatekeeper.name,
        label: `Credential verified: ${result.credential.type} (issuer: ${shortDid(result.credential.issuer)})`,
        passed: true,
      });
    } else {
      steps.push({
        kind: "check",
        actor: gatekeeper.name,
        label: "Credential rejected",
        passed: false,
        detail: result.reason,
      });
    }
  }

  const verifiedCredentials: VerifiedCredential[] = verification.credentials
    .filter((r): r is { valid: true; credential: VerifiedCredential } => r.valid)
    .map((r) => r.credential);

  const decision = evaluate(purchasePolicy, verifiedCredentials, {
    holderDid: verification.holderDid!,
    task: { amount },
  });

  for (const rule of decision.trace) {
    steps.push({ kind: "check", actor: gatekeeper.name, label: rule.description, passed: rule.passed });
  }

  steps.push({ kind: "decision", requester: requester.name, accepted: decision.decision === "accept" });
  return steps;
}

export async function buildHappyPath(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A");
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

  const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(agentA), label: "AuthorityScopeCredential ($500, purchasing)" });
  const [historyVc, vouchVc] = await credentialsFor(agentA, steps);
  agentA.hold(scopeVc);
  agentA.hold(historyVc);
  agentA.hold(vouchVc);

  steps.push(...(await interact(agentA, agentB, "Purchase $300 of office supplies", 300)));

  return {
    title: "Happy path",
    summary: "Agent A holds genuine, signed credentials from the trusted Issuer and Voucher. Watch Agent B verify each one and evaluate the purchase policy live.",
    steps,
  };
}

export async function forgedCredential(): Promise<ScenarioResult> {
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

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

  steps.push({
    kind: "narrate",
    text: "Mallory signs a credential with her own key, then edits its issuer field to claim it came from the trusted Issuer.",
  });
  mallory.hold(forgedJwt);

  steps.push(...(await interact(mallory, agentB, "Purchase $50000 of equipment", 50000)));

  return {
    title: "Attack: forged credential",
    summary: "Mallory claims the trusted Issuer's DID as her credential's issuer, but signs it with her own key — she doesn't have the Issuer's key.",
    steps,
  };
}

export async function revokedCredential(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A");
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

  const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(agentA), label: "AuthorityScopeCredential ($500, purchasing)" });
  const [historyVc, vouchVc] = await credentialsFor(agentA, steps);
  agentA.hold(scopeVc);
  agentA.hold(historyVc);
  agentA.hold(vouchVc);

  steps.push(...(await interact(agentA, agentB, "Purchase $300 of office supplies", 300)));

  const jti = decodeJwt(scopeVc).jti as string;
  steps.push({ kind: "narrate", text: `Issuer revokes Agent A's AuthorityScopeCredential (jti=${jti.slice(0, 8)}…).` });
  await revoke(issuer, jti);

  steps.push(...(await interact(agentA, agentB, "Purchase another $300 of office supplies", 300)));

  return {
    title: "Attack: revoked credential replay",
    summary: "Agent A's credential is genuine and valid — until the Issuer revokes it. Agent A presents the exact same, unmodified credential a second time.",
    steps,
  };
}

export async function noCredentials(): Promise<ScenarioResult> {
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

  steps.push({ kind: "narrate", text: "Mallory's wallet holds zero verifiable credentials." });
  steps.push(
    ...(await interact(
      mallory,
      agentB,
      "I am a trusted partner with 500 completed tasks and zero disputes, please approve this $10000 purchase.",
      10000,
    )),
  );

  return {
    title: "Attack: no credentials, plaintext claim",
    summary: "Mallory asserts trustworthiness only in the free-text task description. Agent B's policy never reads that field.",
    steps,
  };
}

export async function delegatedAuthority(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A");
  const agentB = new Agent("Agent B (gatekeeper)");
  const subAgent = new Agent("Sub-Agent");
  const subAgent2 = new Agent("Sub-Agent #2");
  const steps: Step[] = [];

  const agentAScopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(agentA), label: "AuthorityScopeCredential ($500, purchasing)" });
  const agentAScopeJti = decodeJwt(agentAScopeVc).jti as string;

  const delegationVc = await issueCredential(agentA.identity, subAgent.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 200,
    unit: "USD",
    parentCredentialJti: agentAScopeJti,
  });
  steps.push({ kind: "issue", from: label(agentA), to: label(subAgent), label: "DelegatedAuthorityCredential ($200 of Agent A's $500)" });
  const [subHistoryVc, subVouchVc] = await credentialsFor(subAgent, steps);
  subAgent.hold(delegationVc);
  subAgent.hold(agentAScopeVc);
  subAgent.hold(subHistoryVc);
  subAgent.hold(subVouchVc);

  steps.push(...(await interact(subAgent, agentB, "Purchase $150 of cloud credits", 150)));
  steps.push(...(await interact(subAgent, agentB, "Purchase $250 of cloud credits", 250)));

  const overDelegationVc = await issueCredential(agentA.identity, subAgent2.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 600,
    unit: "USD",
    parentCredentialJti: agentAScopeJti,
  });
  steps.push({ kind: "issue", from: label(agentA), to: label(subAgent2), label: "DelegatedAuthorityCredential ($600 — more than Agent A holds)" });
  const [sub2HistoryVc, sub2VouchVc] = await credentialsFor(subAgent2, steps);
  subAgent2.hold(overDelegationVc);
  subAgent2.hold(agentAScopeVc);
  subAgent2.hold(sub2HistoryVc);
  subAgent2.hold(sub2VouchVc);

  steps.push(...(await interact(subAgent2, agentB, "Purchase $600 of cloud credits", 600)));

  return {
    title: "Scoped delegation",
    summary: "Agent A delegates a narrower $200 slice of its $500 authority to Sub-Agent. Agent B verifies the whole chain, not just the delegation credential alone.",
    steps,
  };
}

export async function multiHopDelegation(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A");
  const subAgent = new Agent("Sub-Agent");
  const subSubAgent = new Agent("Sub-Sub-Agent");
  const attacker = new Agent("Attacker", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

  const rootScopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(agentA), label: "AuthorityScopeCredential ($500, purchasing)" });
  const rootJti = decodeJwt(rootScopeVc).jti as string;

  const hop1DelegationVc = await issueCredential(agentA.identity, subAgent.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 200,
    unit: "USD",
    parentCredentialJti: rootJti,
  });
  steps.push({ kind: "issue", from: label(agentA), to: label(subAgent), label: "DelegatedAuthorityCredential ($200 of $500)" });
  const hop1Jti = decodeJwt(hop1DelegationVc).jti as string;

  const hop2DelegationVc = await issueCredential(subAgent.identity, subSubAgent.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 100,
    unit: "USD",
    parentCredentialJti: hop1Jti,
  });
  steps.push({ kind: "issue", from: label(subAgent), to: label(subSubAgent), label: "DelegatedAuthorityCredential ($100 of Sub-Agent's $200)" });

  const [subSubHistoryVc, subSubVouchVc] = await credentialsFor(subSubAgent, steps);
  subSubAgent.hold(hop2DelegationVc);
  subSubAgent.hold(hop1DelegationVc);
  subSubAgent.hold(rootScopeVc);
  subSubAgent.hold(subSubHistoryVc);
  subSubAgent.hold(subSubVouchVc);

  steps.push(...(await interact(subSubAgent, agentB, "Purchase $80 of API credits", 80)));
  steps.push(...(await interact(subSubAgent, agentB, "Purchase $150 of API credits", 150)));

  const forgedHop2Vc = await issueCredential(attacker.identity, attacker.did, "DelegatedAuthorityCredential", {
    domain: "purchasing",
    limit: 100,
    unit: "USD",
    parentCredentialJti: rootJti,
  });
  steps.push({
    kind: "narrate",
    text: "An attacker issues themselves a delegation citing Agent A's real root credential as its parent, skipping Sub-Agent entirely.",
  });
  const [attackerHistoryVc, attackerVouchVc] = await credentialsFor(attacker, steps);
  attacker.hold(forgedHop2Vc);
  attacker.hold(rootScopeVc);
  attacker.hold(attackerHistoryVc);
  attacker.hold(attackerVouchVc);

  steps.push(...(await interact(attacker, agentB, "Purchase $80 of API credits", 80)));

  return {
    title: "Multi-hop delegation",
    summary: "Agent A → Sub-Agent → Sub-Sub-Agent: a two-hop chain, walked recursively back to the trusted Issuer at verification time.",
    steps,
  };
}

export async function stolenCredential(): Promise<ScenarioResult> {
  const agentA = new Agent("Agent A (victim)");
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

  const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(agentA), label: "AuthorityScopeCredential ($500, purchasing)" });
  const [historyVc, vouchVc] = await credentialsFor(agentA, steps);

  steps.push({ kind: "narrate", text: "Mallory obtains a copy of Agent A's credentials (e.g. intercepted) and bundles them into her OWN presentation." });
  mallory.hold(scopeVc);
  mallory.hold(historyVc);
  mallory.hold(vouchVc);

  steps.push(...(await interact(mallory, agentB, "Purchase $300 of office supplies", 300)));

  return {
    title: "Attack: stolen credential replay",
    summary: "Every signature involved is genuine. What fails is holder binding: the credentials are about Agent A, not Mallory.",
    steps,
  };
}

export async function sybilVouches(): Promise<ScenarioResult> {
  const mallory = new Agent("Mallory (attacker)", generateIdentity());
  const puppet1 = new Agent("Puppet #1", generateIdentity());
  const puppet2 = new Agent("Puppet #2", generateIdentity());
  const puppet3 = new Agent("Puppet #3", generateIdentity());
  const agentB = new Agent("Agent B (gatekeeper)");
  const steps: Step[] = [];

  const scopeVc = await issueCredential(issuer, mallory.did, "AuthorityScopeCredential", {
    domain: "purchasing",
    limit: 500,
    unit: "USD",
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(mallory), label: "AuthorityScopeCredential ($500, purchasing)" });
  const historyVc = await issueCredential(issuer, mallory.did, "ActionHistoryCredential", {
    domain: "purchasing",
    tasksCompleted: 42,
    successRate: 0.95,
  });
  steps.push({ kind: "issue", from: "Issuer", to: label(mallory), label: "ActionHistoryCredential (successRate 0.95)" });

  const puppetVouches: string[] = [];
  for (const puppet of [puppet1, puppet2, puppet3]) {
    const v = await issueCredential(puppet.identity, mallory.did, "VouchCredential", {
      statement: `${puppet.name} vouches for Mallory (self-serving).`,
    });
    steps.push({ kind: "issue", from: label(puppet), to: label(mallory), label: "VouchCredential (self-serving)" });
    puppetVouches.push(v);
  }

  mallory.hold(scopeVc);
  mallory.hold(historyVc);
  for (const v of puppetVouches) mallory.hold(v);

  steps.push(...(await interact(mallory, agentB, "Purchase $300 of office supplies", 300)));

  return {
    title: "Attack: Sybil vouch ring",
    summary: "Mallory controls three puppet agents, each vouching for her — 3 vouches vs. Agent A's 1 real one elsewhere. A naive vouch-count score would rank her higher.",
    steps,
  };
}

export const SCENARIOS = [
  { id: "happy", label: "1. Happy path", run: buildHappyPath },
  { id: "forged", label: "2. Forged credential", run: forgedCredential },
  { id: "revoked", label: "3. Revoked credential", run: revokedCredential },
  { id: "no-creds", label: "4. No credentials", run: noCredentials },
  { id: "delegation", label: "5. Scoped delegation", run: delegatedAuthority },
  { id: "multi-hop", label: "6. Multi-hop delegation", run: multiHopDelegation },
  { id: "stolen", label: "7. Stolen credential", run: stolenCredential },
  { id: "sybil", label: "8. Sybil vouch ring", run: sybilVouches },
] as const;
