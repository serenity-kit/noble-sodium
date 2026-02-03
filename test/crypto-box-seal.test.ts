import sodium from "libsodium-wrappers";
import { expect, it } from "vitest";
import { cryptoBoxSeal, cryptoBoxSealOpen } from "../src/index";

const keyPairRecipient = {
  keyType: "x25519",
  publicKey: new Uint8Array([
    115, 19, 194, 43, 251, 66, 115, 92, 240, 227, 4, 141, 167, 179, 252, 121,
    199, 199, 180, 165, 47, 8, 101, 160, 27, 198, 75, 85, 132, 228, 4, 57,
  ]),
  privateKey: new Uint8Array([
    189, 92, 179, 44, 143, 43, 0, 92, 131, 148, 159, 7, 78, 149, 23, 245, 211,
    5, 41, 26, 39, 100, 87, 36, 64, 176, 60, 24, 224, 62, 40, 34,
  ]),
};

const message = new Uint8Array([1, 2, 3, 4, 5]);

it("should perform compatible box seal operations", async () => {
  await sodium.ready;
  const ciphertext = cryptoBoxSeal({
    message,
    publicKey: keyPairRecipient.publicKey,
  });
  const decrypted = cryptoBoxSealOpen({
    ciphertext,
    privateKey: keyPairRecipient.privateKey,
    publicKey: keyPairRecipient.publicKey,
  });
  expect(decrypted).toEqual(message);
});

it("should perform libsodium compatible box seal operations", async () => {
  await sodium.ready;

  const ciphertext = cryptoBoxSeal({
    message,
    publicKey: keyPairRecipient.publicKey,
  });
  const decrypted = sodium.crypto_box_seal_open(
    ciphertext,
    keyPairRecipient.publicKey,
    keyPairRecipient.privateKey,
  );
  expect(decrypted).toEqual(message);

  const ciphertext2 = sodium.crypto_box_seal(
    message,
    keyPairRecipient.publicKey,
  );
  const decrypted2 = cryptoBoxSealOpen({
    ciphertext: ciphertext2,
    privateKey: keyPairRecipient.privateKey,
    publicKey: keyPairRecipient.publicKey,
  });

  expect(decrypted2).toEqual(message);
});
