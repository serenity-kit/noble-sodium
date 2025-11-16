import { blake2b } from "@noble/hashes/blake2.js";
import {
  crypto_box_NONCEBYTES,
  crypto_box_PUBLICKEYBYTES,
} from "./constants.js";
import { cryptoBoxOpenEasy } from "./crypto-box-open-easy.js";

type CryptoBoxSealOpenParams = {
  ciphertext: Uint8Array;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export function cryptoBoxSealOpen({
  ciphertext,
  privateKey,
  publicKey,
}: CryptoBoxSealOpenParams): Uint8Array {
  const ephemeralPublicKey = ciphertext.slice(0, crypto_box_PUBLICKEYBYTES);
  const nonce = blake2b(new Uint8Array([...ephemeralPublicKey, ...publicKey]), {
    dkLen: crypto_box_NONCEBYTES,
  });

  const encryptedMessage = ciphertext.slice(crypto_box_PUBLICKEYBYTES);

  return cryptoBoxOpenEasy({
    ciphertext: encryptedMessage,
    nonce,
    publicKey: ephemeralPublicKey,
    privateKey,
  });
}
