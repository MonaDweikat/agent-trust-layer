/**
 * Revocation layer: lets an issuer invalidate a credential it already signed.
 *
 * A simplified, local stand-in for W3C StatusList2021: instead of a hosted
 * bitstring credential, each issuer keeps a signed list of revoked
 * credential IDs (`jti`s). The list itself is a JWT signed by the issuer, so
 * a verifier reading it can confirm it wasn't tampered with independently of
 * trusting the transport it came over.
 *
 * In-memory + per-process here (a Map), which is enough to demonstrate the
 * mechanism: "revoke this credential" -> re-checked on next verification.
 */

import { SignJWT, importJWK, jwtVerify } from "jose";
import type { AgentIdentity } from "../identity/index.js";
import { resolveDidKey } from "../identity/index.js";
import { toPrivateJwk, toPublicJwk } from "../identity/jwk.js";

interface StatusListPayload {
  statusList: {
    issuer: string;
    revoked: string[]; // credential jtis
    updatedAt: string;
  };
}

// issuerDid -> signed status list JWT
const registries = new Map<string, string>();

async function readList(issuerDid: string): Promise<string[]> {
  const listJwt = registries.get(issuerDid);
  if (!listJwt) return [];
  const publicKey = await importJWK(toPublicJwk(resolveDidKey(issuerDid)), "EdDSA");
  const { payload } = await jwtVerify(listJwt, publicKey);
  return (payload as unknown as StatusListPayload).statusList.revoked;
}

async function writeList(issuer: AgentIdentity, revoked: string[]): Promise<void> {
  const key = await importJWK(toPrivateJwk(issuer), "EdDSA");
  const payload: StatusListPayload = {
    statusList: { issuer: issuer.did, revoked, updatedAt: new Date().toISOString() },
  };
  const listJwt = await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(issuer.did)
    .setIssuedAt()
    .sign(key);
  registries.set(issuer.did, listJwt);
}

/** Issuer revokes a credential it issued, identified by its `jti`. */
export async function revoke(issuer: AgentIdentity, credentialJti: string): Promise<void> {
  const current = await readList(issuer.did);
  if (!current.includes(credentialJti)) {
    current.push(credentialJti);
  }
  await writeList(issuer, current);
}

/**
 * Verifier-facing check: is this credential (issued by issuerDid) revoked?
 * Resolves the issuer's public key from its did:key and verifies the status
 * list's own signature before trusting its contents.
 */
export async function isRevoked(issuerDid: string, credentialJti: string): Promise<boolean> {
  const revoked = await readList(issuerDid);
  return revoked.includes(credentialJti);
}
