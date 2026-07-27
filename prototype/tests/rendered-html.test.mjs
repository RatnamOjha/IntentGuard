import assert from "node:assert/strict";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the IntentGuard operator console", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>IntentGuard \| Financial Agent Governance<\/title>/i);
  assert.match(html, /Financial agent control room/);
  assert.match(html, /Simulate an agent action/);
  assert.match(html, /Stale lease after emergency stop/);
  assert.match(html, /Permission and budget configuration/);
  assert.match(html, /Measured evaluation evidence/);
  assert.match(html, /Production roadmap/i);
  assert.match(html, /Emergency stop/);
  assert.match(html, /Live decisions/);
  assert.doesNotMatch(html, /Your site is taking shape/);
  assert.doesNotMatch(html, /react-loading-skeleton/);
});
