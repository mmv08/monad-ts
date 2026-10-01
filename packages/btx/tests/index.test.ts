import { describe, expect, test } from "bun:test";
import * as publicApi from "../src/index.js";

describe("entry points", () => {
  test("the sender entry excludes test keys and fixed-randomness helpers", () => {
    for (const name of [
      "createTestKey",
      "encryptWithRandom",
      "encryptPadded",
    ]) {
      expect(publicApi).not.toHaveProperty(name);
    }
  });
});
