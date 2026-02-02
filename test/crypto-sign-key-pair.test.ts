import sodium, { type KeyPair } from "libsodium-wrappers";
import { expect, expectTypeOf, it } from "vitest";
import { cryptoSignKeyPair } from "../src/index";

it("should generate compatible keypairs", async () => {
  await sodium.ready;
  const signKeyPair = cryptoSignKeyPair();

  expectTypeOf(signKeyPair).toEqualTypeOf<KeyPair>();
  expect(signKeyPair.keyType).toEqual("ed25519");
  expect(signKeyPair.privateKey.length).toEqual(
    sodium.crypto_sign_SECRETKEYBYTES,
  );
  expect(signKeyPair.publicKey.length).toEqual(
    sodium.crypto_sign_PUBLICKEYBYTES,
  );
});
