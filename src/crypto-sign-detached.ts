import { ed25519 } from "@noble/curves/ed25519.js";

type CryptoSignDetachedParams = {
  message: Uint8Array;
  privateKey: Uint8Array;
};

export function cryptoSignDetached({
  message,
  privateKey,
}: CryptoSignDetachedParams): Uint8Array {
  return ed25519.sign(message, privateKey.slice(0, 32));
}
