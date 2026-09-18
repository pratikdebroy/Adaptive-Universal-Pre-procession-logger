const http = require('http');
const express = require('express');
const cors = require('cors');
const { WebSocketServer, WebSocket } = require('ws');
const axios = require('axios');

const PORT = process.env.PORT || 4000;
const ENGINE_URL = process.env.AEGIS_ENGINE_URL || 'http://127.0.0.1:8080';

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Track connected WebSocket clients
const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  console.log(`[Gateway WS] Client connected (Total: ${clients.size})`);

  ws.send(JSON.stringify({
    type: 'CONNECTION_ESTABLISHED',
    message: 'Connected to AegisLog Real-Time Gateway',
    timestamp: new Date().toISOString()
  }));

  ws.on('close', () => {
    clients.delete(ws);
    console.log(`[Gateway WS] Client disconnected (Total: ${clients.size})`);
  });
});

// Broadcast payload to all active WebSocket clients
function broadcast(message) {
  const payload = JSON.stringify(message);
  for (const client of clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

// REST Endpoints
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'aegislog-gateway', engine_url: ENGINE_URL });
});

app.get('/api/stats', async (req, res) => {
  try {
    const response = await axios.get(`${ENGINE_URL}/api/stats`, { timeout: 3000 });
    res.json(response.data);
  } catch (err) {
    res.status(503).json({
      error: 'Engine unreachable',
      details: err.message,
      total_ingested: 0,
      total_parsed: 0,
      slm_invocations: 0,
      event_quarantine_count: 0,
      parser_quarantine_count: 0
    });
  }
});

app.get('/api/bpt', async (req, res) => {
  try {
    const response = await axios.get(`${ENGINE_URL}/api/bpt`, { timeout: 3000 });
    res.json(response.data);
  } catch (err) {
    res.status(503).json({ error: 'Engine unreachable', details: err.message, leaves: [] });
  }
});

app.get('/api/events', async (req, res) => {
  try {
    const response = await axios.get(`${ENGINE_URL}/api/events`, { timeout: 3000 });
    res.json(response.data);
  } catch (err) {
    res.status(503).json({ error: 'Engine unreachable', details: err.message, events: [] });
  }
});

app.get('/api/quarantine/events', async (req, res) => {
  try {
    const response = await axios.get(`${ENGINE_URL}/api/quarantine/events`, { timeout: 3000 });
    res.json(response.data);
  } catch (err) {
    res.status(503).json({ error: 'Engine unreachable', details: err.message, items: [] });
  }
});

app.get('/api/quarantine/parsers', async (req, res) => {
  try {
    const response = await axios.get(`${ENGINE_URL}/api/quarantine/parsers`, { timeout: 3000 });
    res.json(response.data);
  } catch (err) {
    res.status(503).json({ error: 'Engine unreachable', details: err.message, items: [] });
  }
});

app.post('/api/ingest', async (req, res) => {
  const { raw_log, source } = req.body;
  if (!raw_log) {
    return res.status(400).json({ error: 'raw_log field required' });
  }

  try {
    const response = await axios.post(`${ENGINE_URL}/api/ingest`, {
      raw_log,
      source: source || 'gateway_api'
    }, { timeout: 15000 });

    const result = response.data;
    if (result.success) {
      broadcast({
        type: 'LOG_PARSED',
        event: result.event,
        raw_log
      });
    }

    res.json(result);
  } catch (err) {
    if (err.response && err.response.data) {
      broadcast({
        type: 'LOG_QUARANTINED',
        quarantine: err.response.data.details,
        raw_log
      });
      return res.status(422).json(err.response.data);
    }
    res.status(503).json({ error: 'Engine processing failed', details: err.message });
  }
});

app.post('/api/registry/rollback', async (req, res) => {
  try {
    const response = await axios.post(`${ENGINE_URL}/api/registry/rollback`, req.body, { timeout: 3000 });
    broadcast({ type: 'REGISTRY_ROLLBACK', variant_id: req.body.variant_id });
    res.json(response.data);
  } catch (err) {
    res.status(503).json({ error: 'Rollback failed', details: err.message });
  }
});

// Periodic background telemetry synchronization
const syncTimer = setInterval(async () => {
  if (clients.size === 0) return;
  try {
    const statsRes = await axios.get(`${ENGINE_URL}/api/stats`, { timeout: 1500 });
    broadcast({ type: 'STATS_UPDATE', data: statsRes.data });
  } catch (_) {
    // Engine may be offline or starting
  }
}, 2000);
syncTimer.unref();

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[AegisLog Gateway] Active and listening on http://localhost:${PORT}`);
    console.log(`[AegisLog Gateway] WebSocket stream available at ws://localhost:${PORT}`);
  });
}

module.exports = { app, server, wss, broadcast };
