import { ed25519 } from "@noble/curves/ed25519.js";

type CryptoSignVerifyDetachedParams = {
  signature: Uint8Array;
  message: Uint8Array;
  publicKey: Uint8Array;
};

export function cryptoSignVerifyDetached({
  signature,
  message,
  publicKey,
}: CryptoSignVerifyDetachedParams): boolean {
  return ed25519.verify(signature, message, publicKey);
}
