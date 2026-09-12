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

  // The console is a refund desk: a queue, the case being looked at, and the
  // decision. It opens on a case rather than on an empty state.
  assert.match(html, /Refund desk/i);
  assert.match(html, /File a complaint/i);
  assert.match(html, /Queue/);

  // A case in the queue shows who filed it, what it is worth, and whether
  // anything was attached -- enough to triage without opening it.
  assert.match(html, /ORD-88213/);
  assert.match(html, /R\. Mehta/);
  assert.match(html, /Arrived damaged/);
  assert.match(html, /attached/);

  // The evidence and the complaint are the point of the case view, and the
  // complaint must be labelled as the customer's own unverified words.
  assert.match(html, /Evidence filed/i);
  assert.match(html, /Customer.{1,8}s words/i);
  assert.match(html, /unverified/i);
  assert.match(html, /dinner set arrived/);

  // The agent proposes; the engine decides. Both halves must be on screen.
  assert.match(html, /The agent proposes/i);
  assert.match(html, /Put it through IntentGuard/i);
  assert.match(html, /Decision/);

  assert.match(html, /Emergency stop/);
  assert.match(html, /Every decision, in order/);

  // Marketing panels that diluted the product demo are gone for good.
  assert.doesNotMatch(html, /Production roadmap/i);
  assert.doesNotMatch(html, /Implementation truth/i);
  assert.doesNotMatch(html, /Measured evaluation evidence/i);

  assert.doesNotMatch(html, /Your site is taking shape/);
  assert.doesNotMatch(html, /react-loading-skeleton/);
});
