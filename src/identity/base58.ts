/**
 * Minimal base58btc (Bitcoin alphabet) multibase codec, used only for
 * encoding/decoding did:key identifiers. Multibase prefixes the string with
 * "z" to signal "this is base58btc" per the multibase spec — that's the only
 * piece of the multiformats stack this project actually needs, so it's
 * implemented directly rather than pulling in the multiformats package.
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHABET_MAP = new Map(Array.from(ALPHABET).map((c, i) => [c, i]));

function encode(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }

  let digits = "";
  while (value > 0n) {
    const remainder = value % 58n;
    value = value / 58n;
    digits = ALPHABET[Number(remainder)] + digits;
  }

  let leadingZeros = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros += ALPHABET[0];
  }

  return `z${leadingZeros}${digits}`;
}

function decode(multibase: string): Uint8Array {
  if (!multibase.startsWith("z")) {
    throw new Error(`not a base58btc multibase string: ${multibase}`);
  }
  const input = multibase.slice(1);

  let value = 0n;
  for (const char of input) {
    const digit = ALPHABET_MAP.get(char);
    if (digit === undefined) {
      throw new Error(`invalid base58 character: ${char}`);
    }
    value = value * 58n + BigInt(digit);
  }

  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value = value / 256n;
  }

  for (const char of input) {
    if (char !== ALPHABET[0]) break;
    bytes.unshift(0);
  }

  return new Uint8Array(bytes);
}

export const base58btc = { encode, decode };
