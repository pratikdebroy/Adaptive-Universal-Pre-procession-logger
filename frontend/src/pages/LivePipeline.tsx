import React, { useState, useEffect, useCallback } from 'react';
import { processEvent, getEvents, getMetrics } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCard } from '../components/MetricCard';
import { 
  Play, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldCheck, 
  Cpu, 
  ArrowRight, 
  FileText, 
  X, 
  Copy, 
  ExternalLink, 
  Zap,
  Activity,
  Layers
} from 'lucide-react';

interface StageInfo {
  name: string;
  status: string;
  count: number;
  latency: number;
  processing_mode?: string;
}

export default function LivePipeline() {
  const [events, setEvents] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [inputLog, setInputLog] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Dynamic pipeline stages based on metrics and last execution
  const [stages, setStages] = useState<StageInfo[]>([
    { name: 'INGEST', status: 'active', count: 0, latency: 1.2 },
    { name: 'PRESERVE', status: 'active', count: 0, latency: 0.8 },
    { name: 'ROUTE', status: 'active', count: 0, latency: 0.5 },
    { name: 'PARSE', status: 'active', count: 0, latency: 5.4 },
    { name: 'VALIDATE', status: 'active', count: 0, latency: 2.1 },
    { name: 'NORMALIZE', status: 'active', count: 0, latency: 1.5 },
    { name: 'DELIVER', status: 'active', count: 0, latency: 0.9 },
  ]);

  const fetchEvents = useCallback(async () => {
    try {
      const [eventsRes, metricsRes] = await Promise.all([
        getEvents(30),
        getMetrics()
      ]);

      if (eventsRes?.data?.events) {
        setEvents(eventsRes.data.events);
      }
      if (metricsRes?.data) {
        setMetrics(metricsRes.data);
        setErrorBanner(null);

        // Update pipeline stage counts
        const total = metricsRes.data.total_events || 0;
        const quar = metricsRes.data.quarantine_count || 0;
        setStages(prev => [
          { ...prev[0], count: total },
          { ...prev[1], count: total },
          { ...prev[2], count: total },
          { ...prev[3], count: total },
          { ...prev[4], count: total },
          { ...prev[5], count: Math.max(0, total - quar) },
          { ...prev[6], count: Math.max(0, total - quar) },
        ]);
      }
    } catch (err: any) {
      console.error('Failed to fetch pipeline state:', err);
      setErrorBanner('Backend connection failed. Please ensure the backend is running on http://127.0.0.1:8000');
    }
  }, []);

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  }, [fetchEvents]);

  const handleProcess = async (logToProcess: string) => {
    const raw = logToProcess.trim();
    if (!raw || isProcessing) return;

    setIsProcessing(true);
    setErrorBanner(null);

    try {
      const res = await processEvent(raw, 'manual');
      const data = res.data;
      setLastResult(data);

      // Immediately prepend event to table state for instantaneous UI feedback
      const newEventRow = {
        event_id: data.event_id || ('temp_' + Date.now()),
        raw_sha256: data.raw_sha256 || '',
        parser_id: data.parser_id || (data.quarantine ? 'none' : 'unknown'),
        processing_mode: data.processing_mode || (data.quarantine ? 'QUARANTINED' : 'FAST_PATH'),
        validation_result: data.validation?.result || (data.quarantine ? 'REJECTED' : 'APPROVED'),
        created_at: new Date().toISOString(),
        timestamp: new Date().toISOString(),
        source: 'manual',
        raw_message: raw,
        full_data: data
      };

      setEvents(prev => [newEventRow, ...prev]);

      // Update latencies from actual stage execution
      if (data.stages && Array.isArray(data.stages)) {
        setStages(prev => prev.map(s => {
          const matched = data.stages.find((ds: any) => ds.name === s.name);
          return matched ? { ...s, latency: Number(matched.latency_ms.toFixed(1)) || s.latency } : s;
        }));
      }

      await fetchEvents();
    } catch (err: any) {
      console.error('Ingestion error:', err);
      setErrorBanner(`Ingestion failed: ${err.response?.data?.detail || err.message || 'Check backend connection'}`);
    } finally {
      setIsProcessing(false);
      setInputLog('');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const totalEvents = metrics?.total_events || events.length || 0;
  const fastPathPct = totalEvents > 0
    ? (((metrics?.fast_path_count || 0) / totalEvents) * 100).toFixed(1)
    : '0.0';
  const structuralPct = totalEvents > 0
    ? (((metrics?.structural_count || 0) / totalEvents) * 100).toFixed(1)
    : '0.0';
  const tier3Pct = totalEvents > 0
    ? (((metrics?.tier3_count || 0) / totalEvents) * 100).toFixed(1)
    : '0.0';
  const quarantineRate = totalEvents > 0
    ? (((metrics?.quarantine_count || 0) / totalEvents) * 100).toFixed(1)
    : '0.0';

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-[#06b6d4]" /> Live Pipeline
          </h1>
          <p className="text-xs text-[#9ca3af] mt-0.5">Real-time log stream processing with fast path routing and adaptive healing</p>
        </div>
        <button
          onClick={fetchEvents}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#1a1f2e] hover:bg-[#2d3348] border border-[#2d3348] rounded-lg text-[#9ca3af] hover:text-white transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Error / Warning Alert Banner */}
      {errorBanner && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorBanner}</span>
          </div>
          <button onClick={() => setErrorBanner(null)} className="text-rose-400 hover:text-rose-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Top Metric Cards (5 Cards) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard label="Total Events" value={totalEvents} />
        <MetricCard label="Fast Path %" value={`${fastPathPct}%`} />
        <MetricCard label="Structural %" value={`${structuralPct}%`} />
        <MetricCard label="Tier-3 %" value={`${tier3Pct}%`} />
        <MetricCard label="Quarantine Rate" value={`${quarantineRate}%`} />
      </div>

      {/* Pipeline Stage Visualizer (7 Connected Stages) */}
      <div className="flex items-center justify-between gap-2 bg-[#0a0e1a] p-4 rounded-xl border border-[#2d3348] overflow-x-auto shadow-inner">
        {stages.map((stage, idx) => (
          <React.Fragment key={stage.name}>
            <div className="flex-1 min-w-[100px] bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-3 text-center shadow-sm hover:border-[#06b6d4]/50 transition-colors">
              <div className="text-xs text-[#9ca3af] font-semibold tracking-wider mb-1">{stage.name}</div>
              <div className="flex justify-center mb-1.5">
                <span className={`w-2.5 h-2.5 rounded-full ${stage.status === 'active' ? 'bg-[#22c55e] shadow-[0_0_10px_rgba(34,197,94,0.7)] animate-pulse' : 'bg-gray-600'}`}></span>
              </div>
              <div className="text-base font-bold font-mono text-white">{stage.count}</div>
              <div className="text-[10px] text-[#06b6d4] font-mono mt-0.5">{stage.latency}ms</div>
            </div>
            {idx < stages.length - 1 && (
              <div className="text-[#2d3348] text-sm font-bold shrink-0">→</div>
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Ingestion Console & Preset Actions */}
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-xl p-5 space-y-4 shadow-lg">
        <div className="flex items-center justify-between text-xs text-[#9ca3af]">
          <span className="font-semibold text-white flex items-center gap-1.5">
            <Zap className="w-4 h-4 text-[#06b6d4]" /> Ingestion Terminal
          </span>
          <span className="font-mono text-[11px]">Lossless Verbatim Preservation · SHA-256 Vaulted</span>
        </div>

        {/* Text Input and Primary Process Button */}
        <div className="flex flex-col sm:flex-row gap-3">
          <input 
            type="text" 
            value={inputLog} 
            onChange={e => setInputLog(e.target.value)} 
            onKeyDown={e => e.key === 'Enter' && handleProcess(inputLog)}
            placeholder="Enter raw log message (e.g. SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW)..." 
            className="flex-1 bg-[#0a0e1a] border border-[#2d3348] rounded-lg px-4 py-2.5 font-mono text-xs sm:text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-[#06b6d4] focus:ring-1 focus:ring-[#06b6d4] transition-all"
          />
          <button 
            onClick={() => handleProcess(inputLog)}
            disabled={isProcessing || !inputLog.trim()} 
            className="bg-[#06b6d4] hover:bg-[#06b6d4]/90 disabled:opacity-50 text-[#0a0e1a] font-bold px-7 py-2.5 rounded-lg transition-all flex items-center justify-center gap-2 shrink-0 cursor-pointer text-xs sm:text-sm uppercase tracking-wider"
          >
            {isProcessing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" /> Processing...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" /> Process Event
              </>
            )}
          </button>
        </div>

        {/* Quick Scenario Preset Buttons */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-[#2d3348]/60">
          <span className="text-xs text-[#9ca3af] font-medium mr-1">Quick Scenarios:</span>
          
          <button 
            type="button"
            onClick={() => {
              const log = "SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW";
              setInputLog(log);
              handleProcess(log);
            }} 
            className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 text-[#22c55e] border border-[#22c55e]/30 px-3 py-1.5 rounded-md transition-colors font-medium cursor-pointer"
          >
            LOAD KNOWN FIREWALL LOG
          </button>

          <button 
            type="button"
            onClick={() => {
              const log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW";
              setInputLog(log);
              handleProcess(log);
            }} 
            className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 text-[#a855f7] border border-[#a855f7]/30 px-3 py-1.5 rounded-md transition-colors font-medium cursor-pointer"
          >
            INTRODUCE FORMAT DRIFT
          </button>

          <button 
            type="button"
            onClick={() => {
              const log = "SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW";
              setInputLog(log);
              handleProcess(log);
            }} 
            className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 text-[#06b6d4] border border-[#06b6d4]/30 px-3 py-1.5 rounded-md transition-colors font-medium cursor-pointer"
          >
            REPLAY DRIFTED LOG
          </button>

          <button 
            type="button"
            onClick={() => {
              const log = '{"timestamp": "2026-09-14T01:24:00Z", "level": "INFO", "service": "user-auth", "message": "User login failed"}';
              setInputLog(log);
              handleProcess(log);
            }} 
            className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 border border-[#f59e0b]/50 text-[#f59e0b] px-3 py-1.5 rounded-md transition-colors font-medium cursor-pointer"
          >
            INJECT UNKNOWN LOG
          </button>
        </div>

        {/* Live Feedback Banner from Last Execution */}
        {lastResult && (
          <div className={`p-3.5 rounded-lg border text-xs font-mono transition-all ${
            lastResult.quarantine 
              ? 'bg-rose-950/40 border-rose-800 text-rose-200' 
              : lastResult.processing_mode === 'FAST_PATH'
                ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
                : 'bg-purple-950/30 border-purple-800/60 text-purple-200'
          }`}>
            <div className="flex items-center justify-between mb-1.5 font-bold">
              <span className="flex items-center gap-2">
                {lastResult.quarantine ? (
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                RESULT: {lastResult.processing_mode || (lastResult.quarantine ? 'QUARANTINED' : 'PROCESSED')}
              </span>
              <span className="text-[11px] text-slate-400">
                Latency: {lastResult.stages?.reduce((acc: number, s: any) => acc + (s.latency_ms || 0), 0).toFixed(2)}ms
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 text-[11px] pt-1 border-t border-slate-700/50">
              <div>
                <span className="text-slate-400">Parser:</span> <span className="font-semibold">{lastResult.parser_id || 'none'}</span>
              </div>
              <div>
                <span className="text-slate-400">Validation:</span> <span className="font-semibold text-emerald-400">{lastResult.validation?.result || (lastResult.quarantine ? 'REJECTED' : 'APPROVED')}</span>
              </div>
              <div>
                <span className="text-slate-400">SHA-256:</span> <span className="font-mono text-slate-300">{lastResult.raw_sha256?.substring(0, 10)}...</span>
              </div>
              <div>
                <span className="text-slate-400">Tier Invocations:</span> <span className="font-semibold">{lastResult.tier3_invocations || 0}</span>
              </div>
            </div>

            {lastResult.quarantine && (
              <div className="mt-2 pt-2 border-t border-rose-900/60 text-rose-300">
                Reason: <strong>{lastResult.quarantine.reason}</strong> — {lastResult.quarantine.detail}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Events Stream Table */}
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-xl overflow-hidden shadow-lg">
        <div className="px-5 py-3 border-b border-[#2d3348] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#06b6d4]" /> Ingested Telemetry Feed (Live Trace)
          </h2>
          <span className="text-xs text-[#9ca3af] font-mono">Showing latest {events.length} events</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-[#0a0e1a] border-b border-[#2d3348] text-[#9ca3af] text-xs uppercase font-mono">
              <tr>
                <th className="px-4 py-3 font-semibold">Timestamp</th>
                <th className="px-4 py-3 font-semibold">Source</th>
                <th className="px-4 py-3 font-semibold">Raw Message</th>
                <th className="px-4 py-3 font-semibold">Parser</th>
                <th className="px-4 py-3 font-semibold">Mode</th>
                <th className="px-4 py-3 font-semibold">Status</th>
                <th className="px-4 py-3 font-semibold">SHA-256</th>
                <th className="px-4 py-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d3348] font-mono text-xs">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-[#9ca3af]">
                    No events ingested yet. Use the presets above or enter a log message to begin.
                  </td>
                </tr>
              ) : (
                events.map((evt, i) => (
                  <tr 
                    key={evt.event_id || i} 
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-[#2d3348]/40 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 text-[#9ca3af] whitespace-nowrap">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : (evt.created_at ? new Date(evt.created_at).toLocaleTimeString() : 'now')}
                    </td>
                    <td className="px-4 py-3 text-slate-300">{evt.source || 'syslog'}</td>
                    <td className="px-4 py-3 text-slate-200 truncate max-w-xs font-mono">
                      {evt.raw_message}
                    </td>
                    <td className="px-4 py-3 text-[#06b6d4] font-semibold">{evt.parser_id || 'none'}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={evt.processing_mode || 'UNKNOWN'} />
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        evt.validation_result === 'APPROVED' 
                          ? 'bg-emerald-950/60 text-[#22c55e] border border-emerald-800' 
                          : 'bg-rose-950/60 text-[#ef4444] border border-rose-800'
                      }`}>
                        {evt.validation_result || 'APPROVED'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[#9ca3af]">
                      {evt.raw_sha256 ? `${evt.raw_sha256.substring(0, 8)}...` : 'N/A'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="text-[#06b6d4] hover:text-[#06b6d4]/80 text-xs font-medium"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Drawer / Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-2xl bg-[#0a0e1a] border-l border-[#2d3348] h-full overflow-y-auto p-6 space-y-5 font-mono">
            <div className="flex items-center justify-between border-b border-[#2d3348] pb-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-[#06b6d4]" /> Event Trace & Provenance
                </h3>
                <div className="text-xs text-[#9ca3af] mt-0.5">Event ID: {selectedEvent.event_id}</div>
              </div>
              <button 
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 rounded-lg bg-[#1a1f2e] hover:bg-[#2d3348] text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Raw Event Information */}
            <div className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="text-[#9ca3af] font-bold uppercase">Verbatim Raw Message</span>
                <button 
                  onClick={() => copyToClipboard(selectedEvent.raw_message)}
                  className="flex items-center gap-1 text-[#06b6d4] hover:underline text-[11px]"
                >
                  <Copy className="w-3 h-3" /> {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div className="p-3 bg-[#1a1f2e] border border-[#2d3348] rounded-lg text-xs text-emerald-300 break-all">
                {selectedEvent.raw_message}
              </div>
            </div>

            {/* SHA-256 Provenance Hash */}
            <div className="space-y-1">
              <div className="text-xs text-[#9ca3af] font-bold uppercase">Evidence Vault SHA-256 Digest</div>
              <div className="p-2.5 bg-[#1a1f2e] border border-[#2d3348] rounded-lg text-xs text-sky-400 break-all font-bold">
                {selectedEvent.raw_sha256}
              </div>
            </div>

            {/* Processing Metadata Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-[#1a1f2e] border border-[#2d3348] rounded-lg">
                <div className="text-[#9ca3af] mb-1">Parser Identifier</div>
                <div className="font-bold text-white text-sm">{selectedEvent.parser_id || 'none'}</div>
              </div>
              <div className="p-3 bg-[#1a1f2e] border border-[#2d3348] rounded-lg">
                <div className="text-[#9ca3af] mb-1">Processing Mode</div>
                <div><StatusBadge status={selectedEvent.processing_mode || 'UNKNOWN'} /></div>
              </div>
            </div>

            {/* Trust Gate Checklist if available */}
            {selectedEvent.full_data?.validation?.checks && (
              <div className="space-y-2">
                <div className="text-xs text-[#9ca3af] font-bold uppercase">Trust Gate Invariant Validation Checks</div>
                <div className="space-y-1.5">
                  {selectedEvent.full_data.validation.checks.map((chk: any, idx: number) => (
                    <div key={idx} className="p-2 bg-[#1a1f2e] border border-[#2d3348] rounded flex items-center justify-between text-xs">
                      <span className="text-slate-300">{chk.check_name}</span>
                      <span className={`flex items-center gap-1 font-semibold ${chk.passed ? 'text-[#22c55e]' : 'text-[#ef4444]'}`}>
                        {chk.passed ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                        {chk.passed ? 'PASSED' : 'FAILED'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* OCSF Normalized Structure if available */}
            {selectedEvent.full_data?.ocsf_event && (
              <div className="space-y-2">
                <div className="text-xs text-[#9ca3af] font-bold uppercase">OCSF v1.1.0 Normalized Output</div>
                <pre className="p-3 bg-[#1a1f2e] border border-[#2d3348] rounded-lg text-[11px] text-emerald-300 overflow-x-auto max-h-56">
                  {JSON.stringify(selectedEvent.full_data.ocsf_event, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
