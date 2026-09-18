'use client';

import React, { useState } from 'react';
import { AlertOctagon, Bug, ShieldAlert, FileText, CheckCircle2 } from 'lucide-react';

interface EventQuarantineItem {
  quarantine_id: string;
  event_id: string;
  raw_sha256: string;
  raw_message: string;
  failure_reason: string;
  failed_check: string;
  timestamp: string;
}

interface ParserQuarantineItem {
  quarantine_id: string;
  candidate_id: string;
  target_skeleton: string;
  raw_spec_json: string;
  rejection_stage: string;
  rejection_reason: string;
  timestamp: string;
}

interface DualQuarantineProps {
  eventQuarantine: EventQuarantineItem[];
  parserQuarantine: ParserQuarantineItem[];
}

export default function DualQuarantine({ eventQuarantine, parserQuarantine }: DualQuarantineProps) {
  const [activeTab, setActiveTab] = useState<'events' | 'parsers'>('events');

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col h-[400px]">
      <div className="bg-slate-800/80 px-4 py-2 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-rose-400">
          <ShieldAlert className="w-4 h-4" />
          <span>DUAL QUARANTINE SEGREGATION (STRICT ARCHITECTURAL SEPARATION)</span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setActiveTab('events')}
            className={`px-2.5 py-1 text-xs rounded transition-colors ${
              activeTab === 'events'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Event Quarantine ({eventQuarantine.length})
          </button>
          <button
            onClick={() => setActiveTab('parsers')}
            className={`px-2.5 py-1 text-xs rounded transition-colors ${
              activeTab === 'parsers'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Parser Quarantine ({parserQuarantine.length})
          </button>
        </div>
      </div>

      <div className="p-3 overflow-y-auto flex-1 font-mono text-xs space-y-2">
        {activeTab === 'events' ? (
          eventQuarantine.length === 0 ? (
            <div className="text-slate-500 text-center py-16">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto mb-2" />
              Event Quarantine is clean. No malformed or invalid field events.
            </div>
          ) : (
            eventQuarantine.map((item, idx) => (
              <div key={idx} className="p-2.5 rounded bg-slate-950/70 border border-amber-900/40">
                <div className="flex items-center justify-between text-[11px] mb-1">
                  <span className="text-amber-400 font-bold flex items-center gap-1">
                    <AlertOctagon className="w-3.5 h-3.5" /> {item.failed_check}
                  </span>
                  <span className="text-slate-500 text-[10px]">{new Date(item.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="text-rose-300/90 text-[11px] mb-1">{item.failure_reason}</div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300 break-all text-[11px]">
                  {item.raw_message}
                </div>
              </div>
            ))
          )
        ) : parserQuarantine.length === 0 ? (
          <div className="text-slate-500 text-center py-16">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto mb-2" />
            Parser Quarantine is clean. No unsafe candidate specs rejected.
          </div>
        ) : (
          parserQuarantine.map((item, idx) => (
            <div key={idx} className="p-2.5 rounded bg-slate-950/70 border border-rose-900/40">
              <div className="flex items-center justify-between text-[11px] mb-1">
                <span className="text-rose-400 font-bold flex items-center gap-1">
                  <Bug className="w-3.5 h-3.5" /> REJECTED AT: {item.rejection_stage}
                </span>
                <span className="text-slate-500 text-[10px]">{new Date(item.timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="text-amber-300/90 text-[11px] mb-1 font-semibold">{item.rejection_reason}</div>
              <div className="text-slate-400 text-[10px] mb-1">Target Skeleton: <span className="text-slate-200">{item.target_skeleton}</span></div>
              <pre className="p-1.5 rounded bg-slate-900 border border-slate-800 text-rose-200/80 text-[10px] overflow-x-auto whitespace-pre-wrap max-h-24">
                {item.raw_spec_json}
              </pre>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
