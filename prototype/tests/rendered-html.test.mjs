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

test("server-renders the IntentGuard console", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>IntentGuard \| Financial Agent Governance<\/title>/i);

  // The page states what the product does before asking for any interaction.
  assert.match(html, /Your support agent can issue/);
  assert.match(html, /It cannot issue the wrong ones/);

  // Two numbered steps, so a first-time viewer knows where to start.
  assert.match(html, /Choose a request/i);
  assert.match(html, /Read the decision/i);

  // Every scenario states its own expected outcome up front.
  // React escapes the apostrophe, so match around it.
  assert.match(html, /A refund above the agent&#x27;s limit/);
  assert.match(html, /The billing agent tries to refund/);
  assert.match(html, /A refund after the emergency stop/);

  // The refusal is the hero, so the empty state must promise the explanation.
  assert.match(html, /the exact rule that fired and the number that broke it/);

  assert.match(html, /Emergency stop/);
  assert.match(html, /Every decision, in order/);

  // Marketing panels that diluted the product demo are gone for good.
  assert.doesNotMatch(html, /Production roadmap/i);
  assert.doesNotMatch(html, /Implementation truth/i);
  assert.doesNotMatch(html, /Measured evaluation evidence/i);

  assert.doesNotMatch(html, /Your site is taking shape/);
  assert.doesNotMatch(html, /react-loading-skeleton/);
});
