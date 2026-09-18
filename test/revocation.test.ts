import { decodeJwt } from "jose";
import { generateIdentity } from "../src/identity/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { revoke, isRevoked } from "../src/revocation/index.js";

const issuer = generateIdentity();
const agentA = generateIdentity();

const vcJwt = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
const jti = decodeJwt(vcJwt).jti as string;

console.log("Before revoke, isRevoked:", await isRevoked(issuer.did, jti), "(expect false)");

await revoke(issuer, jti);

console.log("After revoke, isRevoked:", await isRevoked(issuer.did, jti), "(expect true)");

console.log(
  "Unrelated credential from same issuer stays unaffected:",
  await isRevoked(issuer.did, "some-other-jti"),
  "(expect false)",
);
