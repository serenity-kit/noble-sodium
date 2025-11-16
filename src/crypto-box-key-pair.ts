import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { crypto_box_SECRETKEYBYTES } from "./constants.js";
import type { KeyPair } from "./types.js";

export function cryptoBoxKeyPair(): KeyPair {
  const privateKey = randomBytes(crypto_box_SECRETKEYBYTES);
  const publicKey = x25519.getPublicKey(privateKey);
  return { keyType: "x25519", publicKey, privateKey };
}
