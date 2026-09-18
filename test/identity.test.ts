import { generateIdentity, resolveDidKey, sign, verify } from "../src/identity/index.js";

const alice = generateIdentity();
const bob = generateIdentity();

console.log("Alice DID:", alice.did);
console.log("Bob DID:  ", bob.did);

const recovered = resolveDidKey(alice.did);
const roundTripOk = Buffer.from(recovered).equals(Buffer.from(alice.publicKey));
console.log("did:key round-trip matches public key:", roundTripOk);

const message = new TextEncoder().encode("transfer $300 to vendor X");
const sig = sign(alice.privateKey, message);
console.log("Signature valid for correct message:", verify(alice.publicKey, message, sig));

const tampered = new TextEncoder().encode("transfer $9000 to vendor X");
console.log("Signature valid for tampered message (should be false):", verify(alice.publicKey, tampered, sig));

console.log("Signature valid under Bob's key (should be false):", verify(bob.publicKey, message, sig));

if (!roundTripOk) process.exit(1);
