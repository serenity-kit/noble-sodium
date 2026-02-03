import sodium from "libsodium-wrappers";
import { expect, it } from "vitest";
import {
  cryptoSignDetached,
  cryptoSignKeyPair,
  cryptoSignVerifyDetached,
} from "../src/index";

it("should perform a working sign and verify operation", async () => {
  await sodium.ready;
  const message = new Uint8Array([1, 2, 3, 4, 5]);
  const keyPair = cryptoSignKeyPair();

  const signature = cryptoSignDetached({
    message,
    privateKey: keyPair.privateKey,
  });
  const isValid = cryptoSignVerifyDetached({
    signature,
    message,
    publicKey: keyPair.publicKey,
  });
  expect(isValid).toStrictEqual(true);
});

it("should perform libsodium compatible sign and verify operation", async () => {
  await sodium.ready;
  const message = new Uint8Array([1, 2, 3, 4, 5]);
  const keyPair = cryptoSignKeyPair();

  const signature = cryptoSignDetached({
    message,
    privateKey: keyPair.privateKey,
  });
  const isValid = sodium.crypto_sign_verify_detached(
    signature,
    message,
    keyPair.publicKey,
  );
  expect(isValid).toStrictEqual(true);

  const signatureLibsodium = sodium.crypto_sign_detached(
    message,
    keyPair.privateKey,
  );
  const isValid2 = cryptoSignVerifyDetached({
    signature: signatureLibsodium,
    message,
    publicKey: keyPair.publicKey,
  });
  expect(isValid2).toStrictEqual(true);
});
