/**
 * Demo: attack #1 — forged credential.
 *
 * Mallory wants Agent B to believe she holds a scope credential from the
 * trusted Issuer. She builds a credential JWT payload that claims
 * `iss: <trusted issuer's DID>`, but she signs it with her own private key —
 * she does not have the Issuer's key. Agent B's verification layer resolves
 * the claimed issuer DID to its real public key and finds the signature
 * doesn't match, rejecting the credential before policy evaluation ever runs.
 */

import { Agent } from "../src/agents/index.js";
import { generateIdentity } from "../src/identity/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { issuer, purchasePolicy, printHeader, printDecision } from "./common.js";

printHeader("Scenario: forged credential");

const mallory = new Agent("Mallory (attacker)", generateIdentity());
const agentB = new Agent("Agent B (gatekeeper)");

// Mallory signs a credential with her OWN key, then splices in the trusted
// issuer's DID as `iss` without re-signing — simulating a forged claim of
// provenance rather than a real compromise of the issuer's key.
const selfSigned = await issueCredential(mallory.identity, mallory.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 999999,
  unit: "USD",
});
const [header, payload, signature] = selfSigned.split(".");
const decodedPayload = JSON.parse(Buffer.from(payload, "base64url").toString());
decodedPayload.iss = issuer.did; // claim to be the trusted issuer
decodedPayload.vc.credentialSubject.id = mallory.did;
const forgedJwt = `${header}.${Buffer.from(JSON.stringify(decodedPayload)).toString("base64url")}.${signature}`;

mallory.hold(forgedJwt);

console.log(`Mallory (${mallory.did}) requests: "Purchase $50000 of equipment", presenting a credential claiming issuer ${issuer.did}`);
const request = await mallory.requestTask("purchase", "Purchase $50000 of equipment", { amount: 50000 });

const decision = await agentB.evaluateRequest(request, purchasePolicy);
printDecision("Mallory", decision, "credential claims the trusted issuer but is signed by Mallory's own key");
