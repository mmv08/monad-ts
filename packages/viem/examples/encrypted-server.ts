import type { Hex } from "viem";
import { createMock } from "../test/encrypted/mock.js";

const mock = createMock();
const bundle = await Bun.build({
  entrypoints: [new URL("./encrypted-browser.ts", import.meta.url).pathname],
  target: "browser",
});
if (!bundle.success)
  throw new AggregateError(bundle.logs, "Browser build failed");
const script = bundle.outputs[0];
if (!script) throw new Error("Missing browser output");

Bun.serve({
  hostname: "127.0.0.1",
  port: 8545,
  maxRequestBodySize: 512 * 1024,
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/")
      return new Response(
        `<!doctype html><meta charset="utf-8"><title>ETX mock</title><h1>Encrypted transaction mock</h1><pre id="result">Running local encryption…</pre><script type="module">import { result } from "/example.js"; document.querySelector("#result").textContent = result;</script>`,
        { headers: { "content-type": "text/html" } },
      );
    if (path === "/example.js")
      return new Response(script, {
        headers: { "content-type": "text/javascript" },
      });
    if (path !== "/rpc" || request.method !== "POST")
      return new Response("Not found", { status: 404 });
    const origin = request.headers.get("origin");
    if (origin && origin !== "http://127.0.0.1:8545")
      return new Response("Invalid origin", { status: 403 });
    let id: unknown = null;
    try {
      // A malformed body throws here or in the mock and gets an error reply.
      const body = (await request.json()) as {
        id: unknown;
        method: string;
        params?: unknown;
      };
      id = body.id;
      const result = await mock.request(body);
      // The example mines each accepted transaction at once.
      if (body.method === "eth_sendRawTransaction") mock.include(result as Hex);
      return Response.json({ jsonrpc: "2.0", id, result });
    } catch (error) {
      return Response.json({
        jsonrpc: "2.0",
        id,
        error: {
          code:
            error && typeof error === "object" && "code" in error
              ? error.code
              : -32603,
          message: error instanceof Error ? error.message : "Invalid request",
          data:
            error && typeof error === "object" && "data" in error
              ? error.data
              : undefined,
        },
      });
    }
  },
});
console.log(
  "Local ETX mock: http://127.0.0.1:8545 (scripted receipts, no EVM execution)",
);
