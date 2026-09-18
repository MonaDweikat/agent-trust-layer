import { importJWK, jwtVerify, decodeJwt } from "jose";
import { generateIdentity } from "../src/identity/index.js";
import { toPublicJwk } from "../src/identity/jwk.js";
import { issueCredential, createPresentation } from "../src/credentials/index.js";

const issuer = generateIdentity();
const agentA = generateIdentity();

const vcJwt = await issueCredential(
  issuer,
  agentA.did,
  "AuthorityScopeCredential",
  { domain: "purchasing", limit: 500, unit: "USD" },
  { expiresInSeconds: 3600 },
);

console.log("Issued VC-JWT (truncated):", vcJwt.slice(0, 60) + "...");

const decoded = decodeJwt(vcJwt);
console.log("Decoded claims match:", JSON.stringify((decoded as any).vc.credentialSubject));

const issuerPubKey = await importJWK(toPublicJwk(issuer.publicKey), "EdDSA");
const { payload } = await jwtVerify(vcJwt, issuerPubKey);
console.log("Signature verifies against issuer's public key:", payload.iss === issuer.did);

// tamper check: verifying against a different (wrong) public key must fail
const mallory = generateIdentity();
const malloryPubKey = await importJWK(toPublicJwk(mallory.publicKey), "EdDSA");
try {
  await jwtVerify(vcJwt, malloryPubKey);
  console.log("Signature verifies under wrong key (should NOT happen): true — BUG");
} catch {
  console.log("Signature correctly rejected under wrong key: true");
}

// presentation bundling
const vpJwt = await createPresentation(agentA, [vcJwt]);
const agentAPubKey = await importJWK(toPublicJwk(agentA.publicKey), "EdDSA");
const { payload: vpPayload } = await jwtVerify(vpJwt, agentAPubKey);
console.log(
  "VP verifies and contains 1 credential:",
  (vpPayload as any).vp.verifiableCredential.length === 1,
);
