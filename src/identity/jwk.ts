/**
 * Adapts this project's raw Ed25519 keys (from @noble/curves) into the OKP
 * JWK shape `jose` expects, so credential signing (src/credentials) can use
 * a standard JWT library instead of hand-rolling JWT framing.
 */

import type { AgentIdentity } from "./index.js";

/** Cross-platform (Node + browser) base64url encoding — no Buffer dependency. */
function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Private JWK (includes `d`) — used only by the identity that owns the key, to sign. */
export function toPrivateJwk(identity: AgentIdentity) {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64url(identity.publicKey),
    d: base64url(identity.privateKey),
  } as const;
}

/** Public JWK — used by any verifier to check a signature. */
export function toPublicJwk(publicKey: Uint8Array) {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64url(publicKey),
  } as const;
}
