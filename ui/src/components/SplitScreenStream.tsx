'use client';

import React from 'react';
import { Terminal, Code2, Lock } from 'lucide-react';

interface ParsedLogItem {
  raw_log: string;
  event: any;
  timestamp?: string;
}

interface SplitScreenProps {
  logs: ParsedLogItem[];
  onSelectEvent?: (event: any) => void;
}

export default function SplitScreenStream({ logs, onSelectEvent }: SplitScreenProps) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col h-[520px]">
      <div className="bg-slate-800/80 px-4 py-2 border-b border-slate-700 flex items-center justify-between text-xs font-semibold">
        <div className="flex items-center gap-2 text-sky-400">
          <Terminal className="w-4 h-4" />
          <span>INCOMING RAW STREAM (BOUNDED & SHA-256 VAULTED)</span>
        </div>
        <div className="flex items-center gap-2 text-emerald-400">
          <Code2 className="w-4 h-4" />
          <span>NORMALIZED OCSF v1.1.0 (PII MASKED & MERKLE PROVED)</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-800 flex-1 overflow-hidden font-mono text-xs">
        {/* Left: Raw Log Column */}
        <div className="p-3 overflow-y-auto space-y-2.5 bg-slate-950/60">
          {logs.length === 0 ? (
            <div className="text-slate-500 text-center py-16">Waiting for streaming logs...</div>
          ) : (
            logs.map((item, idx) => (
              <div
                key={idx}
                onClick={() => onSelectEvent && onSelectEvent(item.event)}
                className="p-2.5 rounded bg-slate-900 border border-slate-800/80 hover:border-sky-500/50 cursor-pointer transition-colors"
              >
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span>FRAME #{logs.length - idx}</span>
                  <span className="truncate max-w-[200px]">SHA: {item.event?.unmapped?.raw_event_hash?.slice(0, 16)}...</span>
                </div>
                <div className="text-slate-300 break-all">{item.raw_log}</div>
              </div>
            ))
          )}
        </div>

        {/* Right: Normalized OCSF Column */}
        <div className="p-3 overflow-y-auto space-y-2.5 bg-slate-950/40">
          {logs.length === 0 ? (
            <div className="text-slate-500 text-center py-16">No normalized OCSF events yet</div>
          ) : (
            logs.map((item, idx) => (
              <div
                key={idx}
                onClick={() => onSelectEvent && onSelectEvent(item.event)}
                className="p-2.5 rounded bg-slate-900/90 border border-emerald-900/40 hover:border-emerald-500/50 cursor-pointer transition-colors"
              >
                <div className="flex items-center justify-between text-[10px] text-emerald-400/90 mb-1">
                  <span className="font-bold">OCSF CLASS {item.event?.class_uid} ({item.event?.category_uid})</span>
                  <span className="flex items-center gap-1 text-[10px] text-slate-400">
                    <Lock className="w-3 h-3 text-emerald-400" /> PII Masked
                  </span>
                </div>
                <pre className="text-emerald-300/90 text-[11px] overflow-x-auto whitespace-pre-wrap max-h-36">
                  {JSON.stringify(item.event, null, 2)}
                </pre>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
