'use client';

import React, { useState } from 'react';
import { GitBranch, RotateCcw, Check, ArrowRight, Shield } from 'lucide-react';

interface ParserVariant {
  variant_id: string;
  name: string;
  regex_pattern: string;
  type_constraint: string;
  match_count: number;
  version: number;
  is_active: boolean;
}

interface BptLeaf {
  skeleton_id: string;
  skeleton_string: string;
  token_count: number;
  variants: ParserVariant[];
}

interface BdptInspectorProps {
  leaves: BptLeaf[];
  onRollbackVariant?: (variantId: string) => void;
}

export default function BdptInspector({ leaves, onRollbackVariant }: BdptInspectorProps) {
  const [selectedLeaf, setSelectedLeaf] = useState<BptLeaf | null>(null);

  const activeLeaf = selectedLeaf || leaves[0] || null;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col h-[400px]">
      <div className="bg-slate-800/80 px-4 py-2 border-b border-slate-700 flex items-center justify-between text-xs font-semibold text-cyan-400">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4" />
          <span>BIDIRECTIONAL PATTERN TREE (BDPT) & PARSER REGISTRY</span>
        </div>
        <span className="text-[11px] text-slate-400">Head-and-Tail Inward Token Matching</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-800 flex-1 overflow-hidden font-mono text-xs">
        {/* Left: Skeleton Family List */}
        <div className="p-2.5 overflow-y-auto space-y-1.5 bg-slate-950/60">
          <div className="text-[10px] text-slate-500 uppercase font-bold px-1 mb-1">Structural Skeletons</div>
          {leaves.length === 0 ? (
            <div className="text-slate-500 text-center py-12">No skeletons registered</div>
          ) : (
            leaves.map((leaf, idx) => (
              <div
                key={idx}
                onClick={() => setSelectedLeaf(leaf)}
                className={`p-2 rounded cursor-pointer transition-colors border ${
                  activeLeaf?.skeleton_string === leaf.skeleton_string
                    ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-0.5">
                  <span>{leaf.skeleton_id}</span>
                  <span className="text-cyan-400/90">{leaf.variants?.length || 0} variant(s)</span>
                </div>
                <div className="text-[11px] font-semibold truncate">{leaf.skeleton_string}</div>
              </div>
            ))
          )}
        </div>

        {/* Right: Ordered Leaf Variants (Constrained-first sequential trial) */}
        <div className="p-3 overflow-y-auto space-y-3 col-span-2 bg-slate-950/40">
          <div className="text-[10px] text-slate-500 uppercase font-bold mb-1 flex items-center justify-between">
            <span>Ordered Leaf Variants (Priority: Type Constraint &gt; Match Count)</span>
            {activeLeaf && <span className="text-cyan-400">{activeLeaf.skeleton_string}</span>}
          </div>

          {!activeLeaf || !activeLeaf.variants || activeLeaf.variants.length === 0 ? (
            <div className="text-slate-500 text-center py-12">Select a skeleton to view its priority variants</div>
          ) : (
            activeLeaf.variants.map((v, vIdx) => (
              <div key={v.variant_id} className="p-3 rounded bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-sky-950 text-sky-300 border border-sky-800">
                      TRIAL #{vIdx + 1}
                    </span>
                    <span className="font-bold text-slate-200">{v.name}</span>
                    <span className="text-[10px] text-slate-400">v{v.version}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/70 text-purple-300 border border-purple-800">
                      Type: {v.type_constraint}
                    </span>
                    <span className="text-[10px] text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/60">
                      {v.match_count} Matches
                    </span>
                    {onRollbackVariant && v.version > 1 && (
                      <button
                        onClick={() => onRollbackVariant(v.variant_id)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-amber-300 transition-colors"
                        title="Roll back to previous active version"
                      >
                        <RotateCcw className="w-3 h-3" /> Rollback
                      </button>
                    )}
                  </div>
                </div>

                <div className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-emerald-400/90 break-all">
                  {v.regex_pattern}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
