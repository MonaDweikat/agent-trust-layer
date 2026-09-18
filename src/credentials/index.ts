/**
 * Credentials layer: issuing Verifiable Credentials (VC-JWT) and bundling
 * them into Verifiable Presentations.
 *
 * Standard: W3C Verifiable Credentials Data Model, encoded as JWTs (the
 * `vc`/`vp` payload claims below follow the VC-JWT profile of that spec).
 */

import { SignJWT } from "jose";
import { importJWK } from "jose";
import type { AgentIdentity } from "../identity/index.js";
import { toPrivateJwk } from "../identity/jwk.js";
import type { CredentialType, VcPayload, VpPayload } from "./types.js";

export * from "./types.js";

export interface IssueOptions {
  /** Credential lifetime from now, in seconds. Omit for a non-expiring credential. */
  expiresInSeconds?: number;
}

/**
 * An issuer signs a credential about a subject. The returned string is a
 * compact JWT: header.payload.signature, signed with the issuer's Ed25519 key.
 */
export async function issueCredential(
  issuer: AgentIdentity,
  subjectDid: string,
  type: CredentialType,
  claims: Record<string, unknown>,
  opts: IssueOptions = {},
): Promise<string> {
  const key = await importJWK(toPrivateJwk(issuer), "EdDSA");

  const vcPayload: VcPayload = {
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", type],
      credentialSubject: { id: subjectDid, ...claims },
    },
  };

  let jwt = new SignJWT({ ...vcPayload })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(issuer.did)
    .setSubject(subjectDid)
    .setJti(crypto.randomUUID())
    .setIssuedAt();

  if (opts.expiresInSeconds) {
    jwt = jwt.setExpirationTime(Math.floor(Date.now() / 1000) + opts.expiresInSeconds);
  }

  return jwt.sign(key);
}

/**
 * A holder bundles credentials it holds into a signed Verifiable
 * Presentation, proving it is indeed the entity presenting them (the VP is
 * signed with the holder's own key, separately from each credential's own
 * issuer signature).
 */
export async function createPresentation(
  holder: AgentIdentity,
  credentialJwts: string[],
): Promise<string> {
  const key = await importJWK(toPrivateJwk(holder), "EdDSA");

  const vpPayload: VpPayload = {
    vp: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      verifiableCredential: credentialJwts,
    },
  };

  return new SignJWT({ ...vpPayload })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(holder.did)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .sign(key);
}
