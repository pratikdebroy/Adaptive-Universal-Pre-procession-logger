import React, { useState, useEffect } from 'react';
import { processEvent, getEvents, getMetrics } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCard } from '../components/MetricCard';

const PipelineStage = ({ name, status, count, latency }: any) => (
  <div className="flex-1 bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-3 text-center shadow-sm">
    <div className="text-xs text-[#9ca3af] font-medium mb-1">{name}</div>
    <div className="flex justify-center mb-1">
      <span className={`w-2 h-2 rounded-full ${status === 'active' ? 'bg-[#22c55e] shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-gray-600'}`}></span>
    </div>
    <div className="text-sm font-mono">{count}</div>
    <div className="text-[10px] text-[#9ca3af]">{latency}ms</div>
  </div>
);

export default function LivePipeline() {
  const [events, setEvents] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [inputLog, setInputLog] = useState('');
  
  const fetchEvents = () => {
    getEvents(20).then(res => setEvents(res.data?.events || [])).catch(console.error);
    getMetrics().then(res => setMetrics(res.data)).catch(console.error);
  };
  
  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleProcess = (log: string) => {
    if (!log.trim()) return;
    processEvent(log, 'manual').then((res) => {
      fetchEvents();
      if (res.data?.quarantine) {
        alert(`Event Quarantined!\nReason: ${res.data.quarantine.reason}\nDetail: ${res.data.quarantine.detail}`);
      }
    }).catch(console.error);
    setInputLog('');
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Live Pipeline</h1>
      </div>
      
      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Total Events" value={metrics?.total_events || 0} />
        <MetricCard label="Fast Path %" value={`${((metrics?.fast_path_count || 0) / (metrics?.total_events || 1) * 100).toFixed(1)}%`} />
        <MetricCard label="Structural %" value={`${((metrics?.structural_count || 0) / (metrics?.total_events || 1) * 100).toFixed(1)}%`} />
        <MetricCard label="Tier-3 %" value={`${((metrics?.tier3_count || 0) / (metrics?.total_events || 1) * 100).toFixed(1)}%`} />
        <MetricCard label="Quarantine Rate" value={`${((metrics?.quarantine_count || 0) / (metrics?.total_events || 1) * 100).toFixed(1)}%`} />
      </div>

      <div className="flex items-center justify-between gap-2 bg-[#0a0e1a] p-4 rounded-xl border border-[#2d3348]">
        <PipelineStage name="INGEST" status="active" count={metrics?.total_events || 0} latency={1.2} />
        <div className="text-[#2d3348]">→</div>
        <PipelineStage name="PRESERVE" status="active" count={metrics?.total_events || 0} latency={0.8} />
        <div className="text-[#2d3348]">→</div>
        <PipelineStage name="ROUTE" status="active" count={metrics?.total_events || 0} latency={0.5} />
        <div className="text-[#2d3348]">→</div>
        <PipelineStage name="PARSE" status="active" count={metrics?.total_events || 0} latency={5.4} />
        <div className="text-[#2d3348]">→</div>
        <PipelineStage name="VALIDATE" status="active" count={metrics?.total_events || 0} latency={2.1} />
        <div className="text-[#2d3348]">→</div>
        <PipelineStage name="NORMALIZE" status="active" count={(metrics?.total_events || 0) - (metrics?.quarantine_count || 0)} latency={1.5} />
        <div className="text-[#2d3348]">→</div>
        <PipelineStage name="DELIVER" status="active" count={(metrics?.total_events || 0) - (metrics?.quarantine_count || 0)} latency={0.9} />
      </div>
      
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-4 space-y-4">
        <div className="flex gap-4">
          <input 
            type="text" 
            value={inputLog} 
            onChange={e => setInputLog(e.target.value)} 
            onKeyDown={e => e.key === 'Enter' && handleProcess(inputLog)}
            placeholder="Enter raw log message..." 
            className="flex-1 bg-[#0a0e1a] border border-[#2d3348] rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-[#06b6d4]"
          />
          <button onClick={() => handleProcess(inputLog)} className="bg-[#06b6d4] hover:bg-[#06b6d4]/80 text-[#0a0e1a] font-semibold px-6 py-2 rounded-lg transition-colors">PROCESS EVENT</button>
        </div>
        <div className="flex gap-2">
          <button onClick={() => handleProcess("SRC=10.10.1.25 DST=172.16.2.10 PROTO=TCP DPT=443 ACTION=ALLOW")} className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 px-3 py-1.5 rounded transition-colors">LOAD KNOWN FIREWALL LOG</button>
          <button onClick={() => handleProcess("SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW")} className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 px-3 py-1.5 rounded transition-colors">INTRODUCE FORMAT DRIFT</button>
          <button onClick={() => handleProcess("SRC_IP=10.10.1.25 DST_IP=172.16.2.10 PROTO=TCP PORT=443 ACT=ALLOW")} className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 px-3 py-1.5 rounded transition-colors">REPLAY DRIFTED LOG</button>
          <button onClick={() => handleProcess("{\"timestamp\": \"2026-09-14T01:24:00Z\", \"level\": \"INFO\", \"service\": \"user-auth\", \"message\": \"User login failed\"}")} className="text-xs bg-[#2d3348] hover:bg-[#2d3348]/80 border border-[#f59e0b]/50 text-[#f59e0b] px-3 py-1.5 rounded transition-colors">INJECT UNKNOWN LOG</button>
        </div>
      </div>
      
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-[#0a0e1a] border-b border-[#2d3348] text-[#9ca3af]">
            <tr>
              <th className="px-4 py-3 font-medium">Timestamp</th>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Raw Message</th>
              <th className="px-4 py-3 font-medium">Parser</th>
              <th className="px-4 py-3 font-medium">Mode</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">SHA-256</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2d3348]">
            {events.map((evt, i) => (
              <tr key={i} className="hover:bg-[#2d3348]/30">
                <td className="px-4 py-3 text-[#9ca3af] whitespace-nowrap">{evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : new Date(evt.created_at).toLocaleTimeString()}</td>
                <td className="px-4 py-3">{evt.source}</td>
                <td className="px-4 py-3 font-mono text-xs truncate max-w-xs">{evt.raw_message}</td>
                <td className="px-4 py-3">{evt.parser_id || 'Unknown'}</td>
                <td className="px-4 py-3"><StatusBadge status={evt.processing_mode || 'UNKNOWN'} /></td>
                <td className="px-4 py-3">
                  <span className={evt.validation_result === 'APPROVED' ? 'text-[#22c55e]' : 'text-[#ef4444]'}>{evt.validation_result}</span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-[#9ca3af]">{evt.raw_sha256?.substring(0, 8)}...</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
