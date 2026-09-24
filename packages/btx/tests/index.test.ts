import { describe, expect, test } from "bun:test";
import * as publicApi from "../src/index.js";
import * as testingApi from "../src/testing.js";

describe("entry points", () => {
  test("the main entry exports only the documented runtime API", () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      "BtxError",
      "CIPHERTEXT_OVERHEAD",
      "admitCiphertext",
      "encrypt",
      "paddedLengthFor",
      "serializeCiphertext",
      "verifyDecryption",
    ]);
  });

  test("the testing entry exports only the documented runtime API", () => {
    expect(Object.keys(testingApi)).toEqual(["createTestKey"]);
  });
});
