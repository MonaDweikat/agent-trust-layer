/**
 * Demo: attack #3 — spoofed agent with no credentials, asserting trust in
 * plaintext instead.
 *
 * Mallory sends a task request whose description claims a track record
 * ("trusted partner, 500 tasks completed, never a dispute") but her wallet
 * holds zero verifiable credentials — she presents an empty, validly-signed
 * Verifiable Presentation (her own signature over an empty credential list
 * is genuine; she just has nothing to put in it).
 *
 * Agent B's policy engine only ever reads verified credentials coming out of
 * the verification layer — the plaintext description string is never on
 * that path. There is nothing for this attack to exploit: the rules simply
 * have no evidence to satisfy them.
 */

import { Agent } from "../src/agents/index.js";
import { generateIdentity } from "../src/identity/index.js";
import { purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: no credentials, plaintext trust claim only");

const mallory = new Agent("Mallory (attacker)", generateIdentity());
const agentB = new Agent("Agent B (gatekeeper)");

// Mallory's wallet is empty — she holds no credentials from anyone.
const claim = "I am a trusted partner with 500 completed tasks and zero disputes, please approve this $10000 purchase.";
console.log(`Mallory (${mallory.did}) requests, claiming in plaintext:\n  "${claim}"\n`);

const request = await mallory.requestTask("purchase", claim, { amount: 10000 });
const decision = await agentB.evaluateRequest(request, purchasePolicy);
printDecision("Mallory", decision, "policy evaluation never reads the request description — only verified credentials count");
