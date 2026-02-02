import sodium, { type KeyPair } from "libsodium-wrappers";
import { expect, expectTypeOf, it } from "vitest";
import { cryptoBoxKeyPair } from "../src/index";

it("should generate compatible keypairs", async () => {
  await sodium.ready;
  const boxKeyPair = cryptoBoxKeyPair();
  const sodiumBoxKeyPair = sodium.crypto_box_keypair();
  expect(sodiumBoxKeyPair.keyType).toEqual("x25519");

  expectTypeOf(boxKeyPair).toEqualTypeOf<KeyPair>();
  expect(boxKeyPair.keyType).toEqual("x25519");
  expect(boxKeyPair.privateKey.length).toEqual(
    sodium.crypto_box_SECRETKEYBYTES,
  );
  expect(boxKeyPair.publicKey.length).toEqual(sodium.crypto_box_PUBLICKEYBYTES);
});
