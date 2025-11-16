import { hsalsa, secretbox } from "@noble/ciphers/salsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { u32, u8 } from "@noble/hashes/utils.js";

type CryptoBoxEasyParams = {
  message: Uint8Array;
  nonce: Uint8Array;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export function cryptoBoxEasy({
  message,
  nonce,
  publicKey,
  privateKey,
}: CryptoBoxEasyParams): Uint8Array {
  const sharedSecret = x25519.getSharedSecret(privateKey, publicKey);
  // const _utf8ToBytes = (str: string) =>
  //   Uint8Array.from(str.split("").map((c) => c.charCodeAt(0)));
  // const sigma = u32(_utf8ToBytes("expand 32-byte k"));
  const sigma = new Uint32Array([
    1634760805, 857760878, 2036477234, 1797285236,
  ]);
  const output = new Uint32Array(8);
  const zeros = new Uint32Array(4).fill(0);
  hsalsa(sigma, u32(sharedSecret), zeros, output);
  const key = u8(output);
  const box = secretbox(key, nonce);
  return box.seal(message);
}
