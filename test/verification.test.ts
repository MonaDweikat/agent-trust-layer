import { decodeJwt } from "jose";
import { generateIdentity } from "../src/identity/index.js";
import { issueCredential, createPresentation } from "../src/credentials/index.js";
import { verifyCredential, verifyPresentation } from "../src/verification/index.js";
import { revoke } from "../src/revocation/index.js";

const issuer = generateIdentity();
const agentA = generateIdentity();
const mallory = generateIdentity();

// 1. valid credential
const validVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
console.log("1. valid credential:", JSON.stringify(await verifyCredential(validVc)));

// 2. expired credential
const expiredVc = await issueCredential(
  issuer,
  agentA.did,
  "AuthorityScopeCredential",
  { domain: "purchasing", limit: 500, unit: "USD" },
  { expiresInSeconds: -10 },
);
console.log("2. expired credential:", JSON.stringify(await verifyCredential(expiredVc)));

// 3. forged credential — Mallory claims to be the issuer but signs with her own key
const forgedVc = await issueCredential(mallory, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 999999,
  unit: "USD",
});
// splice in the real issuer's DID as `iss` without re-signing (simulates tampering)
const [header, payload] = forgedVc.split(".");
const decodedPayload = JSON.parse(Buffer.from(payload, "base64url").toString());
decodedPayload.iss = issuer.did; // claim to be the trusted issuer
const tamperedPayload = Buffer.from(JSON.stringify(decodedPayload)).toString("base64url");
const tamperedJwt = `${header}.${tamperedPayload}.${forgedVc.split(".")[2]}`;
console.log("3. forged credential (claims issuer, signed by attacker):", JSON.stringify(await verifyCredential(tamperedJwt)));

// 4. revoked credential
const jti = decodeJwt(validVc).jti as string;
await revoke(issuer, jti);
console.log("4. revoked credential:", JSON.stringify(await verifyCredential(validVc)));

// 5. full presentation verification (holder = agentA presents the still-valid... oh wait it's revoked now)
const freshVc = await issueCredential(issuer, agentA.did, "ActionHistoryCredential", {
  domain: "purchasing",
  tasksCompleted: 42,
  successRate: 0.95,
});
const vp = await createPresentation(agentA, [freshVc]);
console.log("5. presentation:", JSON.stringify(await verifyPresentation(vp)));
