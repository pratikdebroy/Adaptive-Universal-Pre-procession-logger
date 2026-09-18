'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Radio, Play, RefreshCw, Send, Zap } from 'lucide-react';
import StatCards from '@/components/StatCards';
import SplitScreenStream from '@/components/SplitScreenStream';
import DualQuarantine from '@/components/DualQuarantine';
import BdptInspector from '@/components/BdptInspector';
import MerkleVerifier from '@/components/MerkleVerifier';

const GATEWAY_HTTP = 'http://localhost:4000';
const GATEWAY_WS = 'ws://localhost:4000';

export default function SOCDashboard() {
  const [wsConnected, setWsConnected] = useState(false);
  const [stats, setStats] = useState({
    total_ingested: 0,
    total_parsed: 0,
    slm_invocations: 0,
    event_quarantine_count: 0,
    parser_quarantine_count: 0,
    registered_skeletons: 2,
    registered_variants: 2,
  });

  const [streamLogs, setStreamLogs] = useState<any[]>([]);
  const [eventQuarantine, setEventQuarantine] = useState<any[]>([]);
  const [parserQuarantine, setParserQuarantine] = useState<any[]>([]);
  const [bptLeaves, setBptLeaves] = useState<any[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [customLog, setCustomLog] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Fetch all pipeline state from gateway
  const refreshData = useCallback(async () => {
    try {
      const [statsRes, bptRes, eqRes, pqRes, eventsRes] = await Promise.all([
        fetch(`${GATEWAY_HTTP}/api/stats`).then((r) => r.json()).catch(() => null),
        fetch(`${GATEWAY_HTTP}/api/bpt`).then((r) => r.json()).catch(() => null),
        fetch(`${GATEWAY_HTTP}/api/quarantine/events`).then((r) => r.json()).catch(() => null),
        fetch(`${GATEWAY_HTTP}/api/quarantine/parsers`).then((r) => r.json()).catch(() => null),
        fetch(`${GATEWAY_HTTP}/api/events`).then((r) => r.json()).catch(() => null),
      ]);

      if (statsRes && !statsRes.error) setStats(statsRes);
      if (Array.isArray(bptRes)) setBptLeaves(bptRes);
      if (Array.isArray(eqRes)) setEventQuarantine(eqRes);
      if (Array.isArray(pqRes)) setParserQuarantine(pqRes);
      if (Array.isArray(eventsRes) && streamLogs.length === 0) {
        setStreamLogs(eventsRes.map((ev) => ({ raw_log: ev.unmapped?.raw_event_hash || 'Archived event', event: ev })));
      }
    } catch (_) {}
  }, [streamLogs.length]);

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 3000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // WebSocket Live Stream Connection
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    function connect() {
      try {
        ws = new WebSocket(GATEWAY_WS);

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'LOG_PARSED') {
              setStreamLogs((prev) => [{ raw_log: msg.raw_log, event: msg.event }, ...prev.slice(0, 49)]);
              setStats((s) => ({ ...s, total_ingested: s.total_ingested + 1, total_parsed: s.total_parsed + 1 }));
            } else if (msg.type === 'LOG_QUARANTINED') {
              setEventQuarantine((prev) => [msg.quarantine, ...prev]);
              setStats((s) => ({ ...s, total_ingested: s.total_ingested + 1, event_quarantine_count: s.event_quarantine_count + 1 }));
            } else if (msg.type === 'STATS_UPDATE' && msg.data) {
              setStats(msg.data);
            }
          } catch (_) {}
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          ws?.close();
        };
      } catch (_) {
        reconnectTimeout = setTimeout(connect, 3000);
      }
    }

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, []);

  const sendLog = async (logLine: string) => {
    if (!logLine.trim()) return;
    setIsSubmitting(true);
    try {
      await fetch(`${GATEWAY_HTTP}/api/ingest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_log: logLine, source: 'soc_dashboard' }),
      });
      await refreshData();
    } catch (_) {}
    setIsSubmitting(false);
  };

  const handleRollback = async (variantId: string) => {
    try {
      await fetch(`${GATEWAY_HTTP}/api/registry/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ variant_id: variantId }),
      });
      await refreshData();
    } catch (_) {}
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 md:p-6 font-mono">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-4 mb-6 gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-sky-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">AEGISLOG PRODUCTION SOC DASHBOARD</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Self-Healing High-Throughput OCSF Pipeline with Bidirectional Pattern Tree (BDPT) & Provenance Ledger
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
            <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-rose-500'}`} />
            <span className={wsConnected ? 'text-emerald-300' : 'text-rose-400'}>
              {wsConnected ? 'GATEWAY WS LIVE' : 'WS RECONNECTING'}
            </span>
          </div>

          <button
            onClick={refreshData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Sync
          </button>
        </div>
      </div>

      {/* Top Telemetry Stats */}
      <StatCards stats={stats} />

      {/* Interactive Demonstration Ingestion Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 mb-6">
        <div className="text-[11px] text-slate-400 uppercase font-bold mb-2 flex items-center justify-between">
          <span className="flex items-center gap-1.5 text-sky-400">
            <Zap className="w-3.5 h-3.5" /> Interactive Ingestion Console (Architecture Verification)
          </span>
          <span className="text-[10px] text-slate-500">Lossless Raw Bounded (Max 64KB)</span>
        </div>

        <div className="flex gap-2 mb-2">
          <input
            type="text"
            placeholder="Type raw syslog / network event payload..."
            value={customLog}
            onChange={(e) => setCustomLog(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendLog(customLog)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
          />
          <button
            onClick={() => {
              sendLog(customLog);
              setCustomLog('');
            }}
            disabled={isSubmitting || !customLog.trim()}
            className="flex items-center gap-1 px-4 py-2 rounded bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold disabled:opacity-50 transition-colors"
          >
            <Send className="w-3.5 h-3.5" /> Ingest
          </button>
        </div>

        {/* Quick Demo Test Presets */}
        <div className="flex flex-wrap gap-2 text-[10px]">
          <span className="text-slate-500 py-1">Quick Scenarios:</span>
          <button
            onClick={() => sendLog('SRC=192.168.1.100 DST=10.0.0.1 DPT=443 ACTION=ALLOW')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-emerald-900/60"
          >
            1. Fast Path (0 SLM)
          </button>
          <button
            onClick={() => sendLog('SRC=192.168.1.105 DST=10.0.0.5 DPT=22 ACTION=BLOCK')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-purple-300 border border-purple-900/60"
          >
            2. Variant Drift (AI -&gt; Same Leaf)
          </button>
          <button
            onClick={() => sendLog('USER=admin SESS=9821 ACCESS=GRANTED HOST=dc01.corp')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-900/60"
          >
            3. New Structure (BDPT Leaf Created)
          </button>
          <button
            onClick={() => sendLog('SRC=999.999.999.999 DST=10.0.0.1 DPT=80 ACTION=ALLOW')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-900/60"
          >
            4. Invalid IP (Event Quarantine)
          </button>
          <button
            onClick={() => sendLog('SRC=10.0.0.1 DST=10.0.0.2 DPT=99999 ACTION=ALLOW')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-300 border border-rose-900/60"
          >
            5. Invalid Port (Event Quarantine)
          </button>
        </div>
      </div>

      {/* Main Split-Screen Stream */}
      <div className="mb-6">
        <SplitScreenStream logs={streamLogs} onSelectEvent={(ev) => setSelectedEvent(ev)} />
      </div>

      {/* Merkle Provenance Verifier */}
      <div className="mb-6">
        <MerkleVerifier selectedEvent={selectedEvent} />
      </div>

      {/* Bottom Grid: BDPT Inspector and Dual Quarantine */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <BdptInspector leaves={bptLeaves} onRollbackVariant={handleRollback} />
        <DualQuarantine eventQuarantine={eventQuarantine} parserQuarantine={parserQuarantine} />
      </div>
    </div>
  );
}
