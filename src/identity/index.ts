/**
 * Identity layer: an agent's self-certifying cryptographic identity.
 *
 * did:key encodes an Ed25519 public key directly into the DID string, so any
 * verifier can recover the key without a resolver, registry, or network call.
 * Format: did:key:z<base58btc(multicodec-prefix || raw-32-byte-pubkey)>
 * The Ed25519 public-key multicodec prefix is the two bytes [0xed, 0x01].
 *
 * Standard: W3C did:key method (https://w3c-ccg.github.io/did-method-key/)
 */

import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "./base58.js";

const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

export interface AgentIdentity {
  did: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generate a fresh Ed25519 keypair and derive its did:key DID. */
export function generateIdentity(): AgentIdentity {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const did = publicKeyToDidKey(publicKey);
  return { did, publicKey, privateKey };
}

/** Encode a raw 32-byte Ed25519 public key as a did:key DID string. */
export function publicKeyToDidKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX, 0);
  prefixed.set(publicKey, ED25519_MULTICODEC_PREFIX.length);
  return `did:key:${base58btc.encode(prefixed)}`;
}

/** Recover the raw 32-byte Ed25519 public key encoded in a did:key DID. */
export function resolveDidKey(did: string): Uint8Array {
  const prefix = "did:key:";
  if (!did.startsWith(prefix)) {
    throw new Error(`not a did:key DID: ${did}`);
  }
  const multibase = did.slice(prefix.length);
  const decoded = base58btc.decode(multibase);
  const [codecByte0, codecByte1] = decoded;
  if (codecByte0 !== ED25519_MULTICODEC_PREFIX[0] || codecByte1 !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new Error(`unsupported did:key codec in ${did}`);
  }
  return decoded.slice(ED25519_MULTICODEC_PREFIX.length);
}

/** Sign arbitrary bytes with an Ed25519 private key. */
export function sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, privateKey);
}

/** Verify an Ed25519 signature against a public key and the original bytes. */
export function verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  return ed25519.verify(signature, data, publicKey);
}
