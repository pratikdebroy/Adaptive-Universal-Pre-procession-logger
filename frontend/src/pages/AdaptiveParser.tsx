import React, { useState, useEffect } from 'react';
import { getEvents } from '../services/api';

export default function AdaptiveParser() {
  const [latestEvent, setLatestEvent] = useState<any>(null);

  useEffect(() => {
    const fetchEvents = () => {
      getEvents(5).then(res => {
        const eventsList = res.data?.events || [];
        const tier3 = eventsList.find((e: any) => e.processing_mode === 'TIER3_ADAPTIVE');
        if (tier3) setLatestEvent(tier3);
      }).catch(console.error);
    };
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-[#06b6d4] to-[#14b8a6]">Adaptive Parser</h1>
          <p className="text-[#9ca3af] mt-2 font-mono tracking-widest text-sm">AI PROPOSES. TRUST GATE DECIDES.</p>
        </div>
      </div>

      <div className="flex items-center justify-between gap-4 bg-[#0a0e1a] p-8 rounded-xl border border-[#2d3348] relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-[#06b6d4] opacity-5 blur-[100px] rounded-full"></div>
        <div className="flex-1 bg-[#1a1f2e] border border-[#2d3348] rounded-xl p-6 text-center shadow-lg relative z-10 hover:border-[#06b6d4]/50 transition-colors">
          <div className="text-[#06b6d4] font-bold mb-2">TIER 1</div>
          <div className="text-sm">TEMPLATE MATCHING</div>
          <div className="text-xs text-[#9ca3af] mt-2 font-mono">&lt; 1ms latency</div>
        </div>
        <div className="text-[#06b6d4] flex flex-col items-center">
          <span className="text-xs mb-1">confident?</span>
          <span>→</span>
        </div>
        <div className="flex-1 bg-[#1a1f2e] border border-[#2d3348] rounded-xl p-6 text-center shadow-lg relative z-10 hover:border-[#f59e0b]/50 transition-colors">
          <div className="text-[#f59e0b] font-bold mb-2">TIER 2</div>
          <div className="text-sm">STRUCTURAL ANALYSIS</div>
          <div className="text-xs text-[#9ca3af] mt-2 font-mono">1-5ms latency</div>
        </div>
        <div className="text-[#f59e0b] flex flex-col items-center">
          <span className="text-xs mb-1">confident?</span>
          <span>→</span>
        </div>
        <div className="flex-1 bg-[#1a1f2e] border border-[#ef4444]/50 rounded-xl p-6 text-center shadow-[0_0_15px_rgba(239,68,68,0.1)] relative z-10 hover:border-[#ef4444] transition-colors">
          <div className="text-[#ef4444] font-bold mb-2 flex items-center justify-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#ef4444] animate-pulse"></span>
            TIER 3
          </div>
          <div className="text-sm">LOCAL SLM + RAG</div>
          <div className="text-xs text-[#9ca3af] mt-2 font-mono text-center">TIER-3 INFERENCE INVOCATIONS</div>
          <div className="text-[10px] text-[#ef4444] mt-1 font-mono">DEMO INFERENCE FALLBACK</div>
        </div>
      </div>

      {latestEvent && (
        <div className="grid grid-cols-2 gap-6 mt-8">
          <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-6 space-y-4">
            <h3 className="font-semibold text-[#06b6d4] mb-4">Semantic Mapping & Extraction</h3>
            <div className="space-y-4">
              <div>
                <h4 className="text-xs text-[#9ca3af] mb-2 uppercase">Variables Identified</h4>
                <div className="flex flex-wrap gap-2">
                  {latestEvent.parser_details?.variables?.map((v: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-[#0a0e1a] border border-[#2d3348] rounded text-xs font-mono">{v}</span>
                  ))}
                  {!latestEvent.parser_details?.variables && <span className="text-xs text-[#9ca3af]">SRC_IP, DST_IP, PROTO, PORT, ACT</span>}
                </div>
              </div>
              <div>
                <h4 className="text-xs text-[#9ca3af] mb-2 uppercase">Constants Identified</h4>
                <div className="flex flex-wrap gap-2">
                  <span className="px-2 py-1 bg-[#0a0e1a] border border-[#2d3348] rounded text-xs font-mono">=</span>
                  <span className="px-2 py-1 bg-[#0a0e1a] border border-[#2d3348] rounded text-xs font-mono">space</span>
                </div>
              </div>
              <div>
                <h4 className="text-xs text-[#9ca3af] mb-2 uppercase">OCSF Semantic Mapping</h4>
                <div className="bg-[#0a0e1a] border border-[#2d3348] rounded p-3 text-xs font-mono space-y-2">
                  <div className="flex justify-between"><span>SRC_IP</span><span className="text-[#06b6d4]">→ source.ip</span></div>
                  <div className="flex justify-between"><span>DST_IP</span><span className="text-[#06b6d4]">→ destination.ip</span></div>
                  <div className="flex justify-between"><span>PORT</span><span className="text-[#06b6d4]">→ destination.port</span></div>
                  <div className="flex justify-between"><span>ACT</span><span className="text-[#06b6d4]">→ activity_name</span></div>
                </div>
              </div>
            </div>
          </div>
          <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-6 flex flex-col">
            <h3 className="font-semibold text-[#14b8a6] mb-4">Parser Specification JSON Output</h3>
            <div className="flex-1 bg-[#0a0e1a] border border-[#2d3348] rounded p-4 overflow-auto">
              <pre className="text-xs font-mono text-[#e5e7eb]">
                {JSON.stringify(latestEvent.parser_details || {
                  "template": "SRC_IP={source.ip} DST_IP={destination.ip} PROTO={network.protocol} PORT={destination.port} ACT={activity_name}",
                  "fields": ["source.ip", "destination.ip", "network.protocol", "destination.port", "activity_name"],
                  "field_types": {
                    "source.ip": "string",
                    "destination.ip": "string",
                    "network.protocol": "string",
                    "destination.port": "integer",
                    "activity_name": "string"
                  },
                  "confidence": 0.92
                }, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
