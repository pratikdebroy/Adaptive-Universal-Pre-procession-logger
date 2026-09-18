const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { app, wss } = require('../src/index.js');

test.after(() => {
  wss.close();
});

test('Gateway health check returns healthy status', async (t) => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  const res = await fetch(`http://127.0.0.1:${port}/health`);
  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'ok');
  assert.strictEqual(data.service, 'aegislog-gateway');

  await new Promise((resolve) => server.close(resolve));
});

test('Gateway rejects invalid ingestion payload', async (t) => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  const res = await fetch(`http://127.0.0.1:${port}/api/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ wrong_key: 'value' })
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.ok(data.error);

  await new Promise((resolve) => server.close(resolve));
});
