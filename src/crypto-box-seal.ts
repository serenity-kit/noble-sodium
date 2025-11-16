import { blake2b } from "@noble/hashes/blake2.js";
import { crypto_box_NONCEBYTES } from "./constants.js";
import { cryptoBoxEasy } from "./crypto-box-easy.js";
import { cryptoBoxKeyPair } from "./crypto-box-key-pair.js";

type CryptoBoxSealParams = {
  message: Uint8Array;
  publicKey: Uint8Array;
};

export function cryptoBoxSeal({
  message,
  publicKey,
}: CryptoBoxSealParams): Uint8Array {
  const ephemeralKeyPair = cryptoBoxKeyPair();
  const nonce = blake2b(
    new Uint8Array([...ephemeralKeyPair.publicKey, ...publicKey]),
    { dkLen: crypto_box_NONCEBYTES },
  );

  const ciphertext = cryptoBoxEasy({
    message,
    nonce,
    publicKey,
    privateKey: ephemeralKeyPair.privateKey,
  });

  return new Uint8Array([...ephemeralKeyPair.publicKey, ...ciphertext]);
}
