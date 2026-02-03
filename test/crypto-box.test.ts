import sodium from "libsodium-wrappers";
import { expect, it } from "vitest";
import { cryptoBoxEasy, cryptoBoxOpenEasy } from "../src/index";

const nonce = new Uint8Array([
  15, 67, 35, 38, 111, 215, 225, 198, 252, 26, 178, 248, 18, 191, 22, 243, 170,
  165, 115, 188, 187, 9, 225, 94,
]);

const keyPairAuthor = {
  keyType: "x25519",
  publicKey: new Uint8Array([
    66, 171, 97, 168, 82, 79, 83, 171, 121, 220, 48, 16, 48, 104, 164, 212, 174,
    150, 58, 156, 246, 135, 48, 97, 153, 74, 171, 32, 200, 130, 97, 124,
  ]),
  privateKey: new Uint8Array([
    226, 10, 233, 65, 6, 250, 173, 118, 6, 174, 16, 249, 35, 237, 120, 111, 247,
    107, 244, 220, 63, 1, 120, 227, 15, 153, 27, 227, 141, 251, 194, 85,
  ]),
};

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

it("should perform compatible box operations", async () => {
  await sodium.ready;

  const encrypted = cryptoBoxEasy({
    message,
    nonce,
    publicKey: keyPairRecipient.publicKey,
    privateKey: keyPairAuthor.privateKey,
  });
  const decrypted = cryptoBoxOpenEasy({
    ciphertext: encrypted,
    nonce,
    publicKey: keyPairAuthor.publicKey,
    privateKey: keyPairRecipient.privateKey,
  });
  expect(decrypted).toEqual(message);
});

it("should perform compatible box operations with libsodium", async () => {
  await sodium.ready;

  const ciphertext = cryptoBoxEasy({
    message,
    nonce,
    publicKey: keyPairRecipient.publicKey,
    privateKey: keyPairAuthor.privateKey,
  });

  const decrypted = sodium.crypto_box_open_easy(
    ciphertext,
    nonce,
    keyPairAuthor.publicKey,
    keyPairRecipient.privateKey,
  );
  expect(decrypted).toEqual(message);

  const ciphertext2 = sodium.crypto_box_easy(
    message,
    nonce,
    keyPairRecipient.publicKey,
    keyPairAuthor.privateKey,
  );

  expect(ciphertext).toEqual(ciphertext2);

  const decrypted2 = cryptoBoxOpenEasy({
    ciphertext: ciphertext2,
    nonce,
    publicKey: keyPairAuthor.publicKey,
    privateKey: keyPairRecipient.privateKey,
  });
  expect(decrypted2).toEqual(message);
});
