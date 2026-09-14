import React, { useState, useEffect } from 'react';
import { getParsers, rollbackParser, promoteParser } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';
import { CheckCircle2, RotateCcw, ChevronDown, ChevronRight, ShieldCheck, Database } from 'lucide-react';

export default function ParserRegistry() {
  const [parsers, setParsers] = useState<any[]>([]);
  const [filter, setFilter] = useState<string>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchParsers = () => {
    getParsers()
      .then((res) => setParsers(res.data?.parsers || []))
      .catch(console.error);
  };

  useEffect(() => {
    fetchParsers();
  }, []);

  const handleApprove = async (id: string, name: string) => {
    try {
      await promoteParser(id);
      setActionMessage(`✓ Parser '${name}' successfully approved and promoted to ACTIVE status!`);
      fetchParsers();
      setTimeout(() => setActionMessage(null), 5000);
    } catch (err: any) {
      alert(`Approval failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleRollback = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to rollback parser '${name}' to its previous version?`)) {
      return;
    }
    try {
      await rollbackParser(id);
      setActionMessage(`↺ Parser '${name}' rolled back to previous version.`);
      fetchParsers();
      setTimeout(() => setActionMessage(null), 5000);
    } catch (err: any) {
      alert(`Rollback failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const filteredParsers = parsers.filter((p) => {
    if (filter === 'ALL') return true;
    return p.status === filter;
  });

  const activeCount = parsers.filter((p) => p.status === 'ACTIVE').length;
  const candidateCount = parsers.filter((p) => p.status === 'CANDIDATE').length;
  const rolledBackCount = parsers.filter((p) => p.status === 'ROLLED_BACK').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Database className="text-[#06b6d4]" />
            Parser Registry & Approval System
          </h1>
          <p className="text-xs text-[#9ca3af] mt-1">
            Deterministic when known · Verified before trust · Atomic SQLite commit + In-memory Fast Path promotion
          </p>
        </div>
        <div className="text-xs font-mono text-[#06b6d4] bg-[#1a1f2e] px-4 py-2 rounded-lg border border-[#2d3348]">
          Dual Mode: Auto Trust Gate & Human-in-the-Loop Approval
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div className="bg-[#22c55e]/15 border border-[#22c55e]/40 text-[#22c55e] px-4 py-3 rounded-lg text-sm flex items-center justify-between font-mono animate-fadeIn">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-xs opacity-60 hover:opacity-100">
            ✕
          </button>
        </div>
      )}

      {/* Metrics Strip */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-4">
          <div className="text-xs text-[#9ca3af] font-medium uppercase">Total Parsers</div>
          <div className="text-2xl font-bold text-[#e5e7eb] mt-1">{parsers.length}</div>
        </div>
        <div className="bg-[#1a1f2e] border border-[#22c55e]/40 rounded-lg p-4">
          <div className="text-xs text-[#22c55e] font-medium uppercase">Active (Fast Path)</div>
          <div className="text-2xl font-bold text-[#22c55e] mt-1">{activeCount}</div>
        </div>
        <div className="bg-[#1a1f2e] border border-[#f59e0b]/40 rounded-lg p-4">
          <div className="text-xs text-[#f59e0b] font-medium uppercase">Candidates (Pending Review)</div>
          <div className="text-2xl font-bold text-[#f59e0b] mt-1">{candidateCount}</div>
        </div>
        <div className="bg-[#1a1f2e] border border-[#ef4444]/40 rounded-lg p-4">
          <div className="text-xs text-[#ef4444] font-medium uppercase">Rolled Back</div>
          <div className="text-2xl font-bold text-[#ef4444] mt-1">{rolledBackCount}</div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 border-b border-[#2d3348] pb-2">
        {['ALL', 'ACTIVE', 'CANDIDATE', 'ROLLED_BACK'].map((tab) => (
          <button
            key={tab}
            onClick={() => setFilter(tab)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filter === tab
                ? 'bg-[#06b6d4]/20 text-[#06b6d4] border border-[#06b6d4]/40'
                : 'text-[#9ca3af] hover:text-[#e5e7eb] hover:bg-[#1a1f2e]'
            }`}
          >
            {tab}
            {tab === 'ACTIVE' && ` (${activeCount})`}
            {tab === 'CANDIDATE' && ` (${candidateCount})`}
            {tab === 'ROLLED_BACK' && ` (${rolledBackCount})`}
          </button>
        ))}
      </div>

      {/* Parsers Table */}
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-[#0a0e1a] border-b border-[#2d3348] text-[#9ca3af]">
            <tr>
              <th className="w-8 px-3 py-3"></th>
              <th className="px-4 py-3 font-medium">Parser ID / Name</th>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Version</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Confidence</th>
              <th className="px-4 py-3 font-medium">Updated</th>
              <th className="px-4 py-3 font-medium text-right">Approval Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2d3348]">
            {filteredParsers.map((parser) => {
              const isExpanded = expandedId === parser.parser_id;
              return (
                <React.Fragment key={parser.parser_id}>
                  <tr className="hover:bg-[#2d3348]/30 group transition-colors">
                    <td className="px-3 py-3 text-center cursor-pointer" onClick={() => setExpandedId(isExpanded ? null : parser.parser_id)}>
                      {isExpanded ? (
                        <ChevronDown size={14} className="text-[#06b6d4]" />
                      ) : (
                        <ChevronRight size={14} className="text-[#9ca3af] group-hover:text-[#e5e7eb]" />
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-semibold text-[#e5e7eb]">{parser.name || parser.parser_id}</div>
                      <div className="font-mono text-[11px] text-[#9ca3af] truncate max-w-xs">{parser.parser_id}</div>
                    </td>
                    <td className="px-4 py-3 text-xs">{parser.source}</td>
                    <td className="px-4 py-3 font-mono text-xs">v{parser.parser_version}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={parser.status} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs font-semibold">
                      {(parser.confidence * 100).toFixed(1)}%
                    </td>
                    <td className="px-4 py-3 text-[#9ca3af] text-xs">
                      {new Date(parser.updated_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2 whitespace-nowrap">
                      {parser.status === 'CANDIDATE' && (
                        <button
                          onClick={() => handleApprove(parser.parser_id, parser.name)}
                          className="inline-flex items-center gap-1.5 text-xs bg-[#22c55e]/15 hover:bg-[#22c55e]/25 text-[#22c55e] border border-[#22c55e]/40 px-3 py-1 rounded transition-colors font-semibold"
                        >
                          <CheckCircle2 size={13} />
                          APPROVE & PROMOTE
                        </button>
                      )}
                      {parser.status === 'ACTIVE' && (
                        <button
                          onClick={() => handleRollback(parser.parser_id, parser.name)}
                          className="inline-flex items-center gap-1.5 text-xs bg-[#ef4444]/15 hover:bg-[#ef4444]/25 text-[#ef4444] border border-[#ef4444]/40 px-3 py-1 rounded transition-colors"
                        >
                          <RotateCcw size={13} />
                          ROLLBACK
                        </button>
                      )}
                      {parser.status === 'ROLLED_BACK' && (
                        <button
                          onClick={() => handleApprove(parser.parser_id, parser.name)}
                          className="inline-flex items-center gap-1.5 text-xs bg-[#f59e0b]/15 hover:bg-[#f59e0b]/25 text-[#f59e0b] border border-[#f59e0b]/40 px-3 py-1 rounded transition-colors font-semibold"
                        >
                          <CheckCircle2 size={13} />
                          RE-ACTIVATE
                        </button>
                      )}
                    </td>
                  </tr>

                  {/* Expanded Specification Inspector */}
                  {isExpanded && (
                    <tr className="bg-[#0a0e1a]/80">
                      <td colSpan={8} className="p-4 border-b border-[#2d3348]">
                        <div className="space-y-3 font-mono text-xs">
                          <div className="flex items-center justify-between text-[#06b6d4] font-semibold">
                            <span className="flex items-center gap-2">
                              <ShieldCheck size={15} />
                              Validated Parser Specification
                            </span>
                            <span className="text-[11px] text-[#9ca3af]">
                              Signature: {parser.format_signature?.substring(0, 16)}...
                            </span>
                          </div>

                          {parser.spec && (
                            <div className="grid grid-cols-2 gap-4 bg-[#111827] p-3 rounded border border-[#2d3348]">
                              <div>
                                <span className="text-[#9ca3af] block mb-1 uppercase text-[10px]">
                                  Template String:
                                </span>
                                <div className="text-[#e5e7eb] bg-[#0a0e1a] p-2 rounded break-all">
                                  {parser.spec.template || 'N/A'}
                                </div>
                              </div>
                              <div>
                                <span className="text-[#9ca3af] block mb-1 uppercase text-[10px]">
                                  Target Field Mappings:
                                </span>
                                <div className="bg-[#0a0e1a] p-2 rounded max-h-32 overflow-y-auto space-y-1">
                                  {parser.spec.fields &&
                                    Object.entries(parser.spec.fields).map(([k, v]) => (
                                      <div key={k} className="flex justify-between text-[11px]">
                                        <span className="text-[#e5e7eb]">{k}</span>
                                        <span className="text-[#06b6d4]">→ {String(v)}</span>
                                      </div>
                                    ))}
                                </div>
                              </div>
                            </div>
                          )}

                          {parser.test_results && Object.keys(parser.test_results).length > 0 && (
                            <div className="bg-[#111827] p-2 rounded border border-[#2d3348]">
                              <span className="text-[#9ca3af] block mb-1 uppercase text-[10px]">
                                Verification Results:
                              </span>
                              <pre className="text-[11px] text-[#22c55e] overflow-x-auto">
                                {JSON.stringify(parser.test_results, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {filteredParsers.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-[#9ca3af]">
                  No parsers found matching filter '{filter}'
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
