// Regenerates vectors.json from the library. Run after a deliberate change to the scheme:
//   bun run packages/btx/tests/fixtures/generate.ts
import { writeFileSync } from "node:fs";
import { renderVectors } from "./vectors.js";

const target = new URL("./vectors.json", import.meta.url);
writeFileSync(target, renderVectors());
console.log(`wrote ${target.pathname}`);
