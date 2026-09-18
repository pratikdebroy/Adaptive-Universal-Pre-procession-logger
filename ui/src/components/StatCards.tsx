'use client';

import React from 'react';
import { ShieldCheck, Cpu, AlertTriangle, Bug, Layers, Activity } from 'lucide-react';

interface StatsProps {
  stats: {
    total_ingested: number;
    total_parsed: number;
    slm_invocations: number;
    event_quarantine_count: number;
    parser_quarantine_count: number;
    registered_skeletons: number;
    registered_variants: number;
  };
}

export default function StatCards({ stats }: StatsProps) {
  const parseRate = stats.total_ingested > 0
    ? ((stats.total_parsed / stats.total_ingested) * 100).toFixed(1)
    : '100.0';

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
          <span>Ingested Logs</span>
          <Activity className="w-4 h-4 text-sky-400" />
        </div>
        <div className="text-xl font-bold text-slate-100">{stats.total_ingested.toLocaleString()}</div>
        <div className="text-[10px] text-slate-500 mt-1">Lossless Raw Bounded</div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
          <span>OCSF Normalized</span>
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-xl font-bold text-emerald-400">{stats.total_parsed.toLocaleString()}</div>
        <div className="text-[10px] text-emerald-500/80 mt-1">{parseRate}% Success Rate</div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
          <span>SLM Self-Heal</span>
          <Cpu className="w-4 h-4 text-purple-400" />
        </div>
        <div className="text-xl font-bold text-purple-400">{stats.slm_invocations}</div>
        <div className="text-[10px] text-purple-500/80 mt-1">Ollama Drift Repaired</div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
          <span>Event Quarantine</span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="text-xl font-bold text-amber-400">{stats.event_quarantine_count}</div>
        <div className="text-[10px] text-amber-500/80 mt-1">Malformed / Invalid Values</div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
          <span>Parser Quarantine</span>
          <Bug className="w-4 h-4 text-rose-400" />
        </div>
        <div className="text-xl font-bold text-rose-400">{stats.parser_quarantine_count}</div>
        <div className="text-[10px] text-rose-500/80 mt-1">Trust Gate ReDoS / Schemas</div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
          <span>BDPT Skeletons</span>
          <Layers className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-xl font-bold text-cyan-400">{stats.registered_skeletons}</div>
        <div className="text-[10px] text-cyan-500/80 mt-1">{stats.registered_variants} Active Variants</div>
      </div>
    </div>
  );
}
