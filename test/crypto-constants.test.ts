import sodium from "libsodium-wrappers";
import { expect, it } from "vitest";
import {
  crypto_box_NONCEBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SEALBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES,
} from "../src/index";

it("should perform compatible box operations", async () => {
  await sodium.ready;

  expect(crypto_box_NONCEBYTES).toEqual(sodium.crypto_box_NONCEBYTES);
  expect(crypto_box_PUBLICKEYBYTES).toEqual(sodium.crypto_box_PUBLICKEYBYTES);
  expect(crypto_box_SECRETKEYBYTES).toEqual(sodium.crypto_box_SECRETKEYBYTES);

  expect(crypto_sign_SECRETKEYBYTES).toEqual(sodium.crypto_sign_SECRETKEYBYTES);
  expect(crypto_sign_PUBLICKEYBYTES).toEqual(sodium.crypto_sign_PUBLICKEYBYTES);

  expect(crypto_box_SEALBYTES).toEqual(sodium.crypto_box_SEALBYTES);
});
