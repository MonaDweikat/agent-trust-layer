/**
 * Verification layer: deciding whether a presented credential is genuine and
 * current. Every check returns a reason string on failure — the policy
 * engine and the demo output both depend on that reason to explain "why" a
 * decision was made, never a bare boolean.
 */

import { importJWK, jwtVerify, decodeJwt, errors as joseErrors } from "jose";
import { resolveDidKey } from "../identity/index.js";
import { toPublicJwk } from "../identity/jwk.js";
import { isRevoked } from "../revocation/index.js";
import type { CredentialType } from "../credentials/types.js";

export interface VerifiedCredential {
  jti: string;
  issuer: string;
  subject: string;
  type: CredentialType;
  credentialSubject: Record<string, unknown>;
}

export type VerificationResult =
  | { valid: true; credential: VerifiedCredential }
  | { valid: false; reason: string };

/**
 * Verify a single credential JWT: signature against the issuer's did:key,
 * structure, expiry, then revocation. Checks run in this order because each
 * later check only makes sense once the earlier ones establish the
 * credential's claims can be trusted at all.
 */
export async function verifyCredential(vcJwt: string): Promise<VerificationResult> {
  let issuerDid: string;
  try {
    const unverified = decodeJwt(vcJwt);
    if (typeof unverified.iss !== "string") {
      return { valid: false, reason: "credential missing issuer (iss)" };
    }
    issuerDid = unverified.iss;
  } catch {
    return { valid: false, reason: "credential is not a well-formed JWT" };
  }

  let issuerPublicKey;
  try {
    issuerPublicKey = await importJWK(toPublicJwk(resolveDidKey(issuerDid)), "EdDSA");
  } catch {
    return { valid: false, reason: `cannot resolve issuer DID: ${issuerDid}` };
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(vcJwt, issuerPublicKey));
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) {
      return { valid: false, reason: "credential has expired" };
    }
    return { valid: false, reason: "signature does not match issuer DID" };
  }

  const vc = (payload as any).vc;
  if (!vc || !Array.isArray(vc.type) || !vc.credentialSubject?.id) {
    return { valid: false, reason: "credential payload is malformed" };
  }

  const jti = payload.jti;
  const subject = payload.sub;
  if (typeof jti !== "string" || typeof subject !== "string") {
    return { valid: false, reason: "credential missing jti or subject (sub)" };
  }

  if (await isRevoked(issuerDid, jti)) {
    return { valid: false, reason: `credential ${jti} was revoked by issuer ${issuerDid}` };
  }

  const type = vc.type[1] as CredentialType;
  return {
    valid: true,
    credential: {
      jti,
      issuer: issuerDid,
      subject,
      type,
      credentialSubject: vc.credentialSubject,
    },
  };
}

export interface PresentationVerificationResult {
  holderValid: boolean;
  holderReason?: string;
  holderDid?: string;
  credentials: VerificationResult[];
}

/**
 * Verify a Verifiable Presentation: check the holder's own signature over
 * the bundle, then verify each contained credential independently.
 */
export async function verifyPresentation(vpJwt: string): Promise<PresentationVerificationResult> {
  let holderDid: string;
  try {
    const unverified = decodeJwt(vpJwt);
    if (typeof unverified.iss !== "string") {
      return { holderValid: false, holderReason: "presentation missing holder (iss)", credentials: [] };
    }
    holderDid = unverified.iss;
  } catch {
    return { holderValid: false, holderReason: "presentation is not a well-formed JWT", credentials: [] };
  }

  let holderPublicKey;
  try {
    holderPublicKey = await importJWK(toPublicJwk(resolveDidKey(holderDid)), "EdDSA");
  } catch {
    return { holderValid: false, holderReason: `cannot resolve holder DID: ${holderDid}`, credentials: [] };
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(vpJwt, holderPublicKey));
  } catch {
    return { holderValid: false, holderReason: "presentation signature does not match holder DID", credentials: [] };
  }

  const vp = (payload as any).vp;
  const credentialJwts: string[] = vp?.verifiableCredential ?? [];

  const results = await Promise.all(credentialJwts.map(verifyCredential));

  return { holderValid: true, holderDid, credentials: results };
}
