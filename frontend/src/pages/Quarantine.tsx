import React, { useState, useEffect } from 'react';
import {
  getQuarantine,
  reprocessQuarantine,
  discardQuarantine,
  approveQuarantine,
  reviewQuarantine,
} from '../services/api';
import { StatusBadge } from '../components/StatusBadge';
import { ShieldAlert, RefreshCw, CheckCircle, Eye, Trash2, X, AlertTriangle, FileCode } from 'lucide-react';

interface QuarantineItem {
  quarantine_id: string;
  event_id: string;
  raw_message: string;
  raw_sha256?: string;
  source: string;
  detected_format?: string;
  reason: string;
  failed_check?: string;
  severity: string;
  detail: string;
  validation_failures?: string[];
  metadata?: Record<string, any>;
  timestamp: string;
  status: string;
}

export default function Quarantine() {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [selectedItem, setSelectedItem] = useState<QuarantineItem | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState<boolean>(false);

  const fetchQ = () => {
    setLoading(true);
    getQuarantine()
      .then((res) => {
        setItems(res.data?.entries || []);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchQ();
    const int = setInterval(fetchQ, 6000);
    return () => clearInterval(int);
  }, []);

  const handleAction = (actionFn: (id: string) => Promise<any>, id: string) => {
    actionFn(id)
      .then(() => {
        fetchQ();
        if (selectedItem?.quarantine_id === id) {
          setSelectedItem(null);
        }
      })
      .catch(console.error);
  };

  const filteredItems = items.filter((item) => {
    if (statusFilter === 'ALL') return true;
    return item.status === statusFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header & Stats */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <ShieldAlert className="w-6 h-6 text-red-400" />
            Ingestion Quarantine & Defense Vault
          </h1>
          <p className="text-xs text-[#9ca3af] mt-1">
            Isolates malformed, unsafe, or resource-exhausting logs while preserving verbatim forensic evidence & SHA-256 integrity.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchQ}
            className="flex items-center gap-1.5 text-xs bg-[#1a1f2e] hover:bg-[#2d3348] text-gray-300 border border-[#2d3348] px-3 py-1.5 rounded transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 border-b border-[#2d3348] pb-2 text-xs font-mono">
        {['ALL', 'QUARANTINED', 'REVIEWED', 'RELEASED', 'DISCARDED'].map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded transition ${
              statusFilter === st
                ? 'bg-[#06b6d4]/20 text-[#06b6d4] border border-[#06b6d4]/40 font-bold'
                : 'text-gray-400 hover:text-gray-200 hover:bg-[#1a1f2e]'
            }`}
          >
            {st} (
            {st === 'ALL'
              ? items.length
              : items.filter((i) => i.status === st).length}
            )
          </button>
        ))}
      </div>

      {/* Main Table */}
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0a0e1a] border-b border-[#2d3348] text-[#9ca3af] uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Event / Source</th>
                <th className="px-4 py-3 font-medium">Format</th>
                <th className="px-4 py-3 font-medium">Quarantine Reason</th>
                <th className="px-4 py-3 font-medium">Failed Check</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d3348]">
              {filteredItems.map((item) => (
                <tr
                  key={item.quarantine_id}
                  className={`hover:bg-[#2d3348]/40 transition cursor-pointer ${
                    selectedItem?.quarantine_id === item.quarantine_id
                      ? 'bg-[#06b6d4]/10 border-l-2 border-[#06b6d4]'
                      : ''
                  }`}
                  onClick={() => setSelectedItem(item)}
                >
                  <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                    {new Date(item.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-cyan-300 font-medium">
                      {item.event_id?.substring(0, 8)}...
                    </div>
                    <div className="text-[10px] text-gray-500 font-mono">
                      src: {item.source}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-300 uppercase">
                    {item.detected_format || 'unknown'}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={item.reason} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-gray-300">
                      {item.failed_check || item.reason}
                    </span>
                    <div className="text-[10px] text-gray-500 truncate max-w-[180px]">
                      {item.detail}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={item.severity || 'MEDIUM'} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={item.status} />
                  </td>
                  <td
                    className="px-4 py-3 text-right space-x-1 whitespace-nowrap"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      onClick={() => setSelectedItem(item)}
                      title="Inspect Event"
                      className="p-1.5 text-gray-400 hover:text-white bg-[#0a0e1a] hover:bg-[#2d3348] border border-[#2d3348] rounded transition"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleAction(reprocessQuarantine, item.quarantine_id)}
                      title="Reprocess through Pipeline"
                      className="px-2 py-1 text-cyan-400 hover:bg-cyan-500/10 border border-cyan-500/30 rounded transition"
                    >
                      REPROCESS
                    </button>
                    {item.status === 'QUARANTINED' && (
                      <button
                        onClick={() => handleAction(reviewQuarantine, item.quarantine_id)}
                        title="Mark as Reviewed"
                        className="px-2 py-1 text-blue-400 hover:bg-blue-500/10 border border-blue-500/30 rounded transition"
                      >
                        REVIEW
                      </button>
                    )}
                    {item.status !== 'RELEASED' && (
                      <button
                        onClick={() => handleAction(approveQuarantine, item.quarantine_id)}
                        title="Approve / Release to Pipeline"
                        className="px-2 py-1 text-emerald-400 hover:bg-emerald-500/10 border border-emerald-500/30 rounded transition"
                      >
                        RELEASE
                      </button>
                    )}
                    {item.status !== 'DISCARDED' && (
                      <button
                        onClick={() => handleAction(discardQuarantine, item.quarantine_id)}
                        title="Discard"
                        className="p-1.5 text-red-400 hover:bg-red-500/10 border border-red-500/30 rounded transition"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {filteredItems.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-gray-500">
                    No quarantined events matching current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Inspection Modal / Drawer */}
      {selectedItem && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-[#1a1f2e] border border-cyan-500/40 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
            {/* Modal Header */}
            <div className="flex justify-between items-start border-b border-[#2d3348] pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-950/50 border border-red-700/50 rounded-lg text-red-400">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white font-mono">
                    QUARANTINED EVENT FORENSIC CARD
                  </h3>
                  <p className="text-xs text-gray-400 font-mono">
                    Event ID: {selectedItem.event_id}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedItem(null)}
                className="text-gray-400 hover:text-white p-1 rounded-md hover:bg-[#2d3348]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Structured Card View (Per Specification Example) */}
            <div className="bg-[#0a0e1a] border border-[#2d3348] rounded-lg p-5 font-mono text-xs space-y-3">
              <div className="flex justify-between items-center border-b border-[#2d3348] pb-2">
                <span className="text-gray-400">Reason:</span>
                <StatusBadge status={selectedItem.reason} />
              </div>

              {selectedItem.metadata?.failed_value !== undefined && (
                <div className="flex justify-between items-center border-b border-[#2d3348] pb-2">
                  <span className="text-gray-400">Failed Value:</span>
                  <span className="text-red-400 font-bold bg-red-950/40 px-2 py-0.5 rounded border border-red-800/40">
                    {String(selectedItem.metadata.failed_value)}
                  </span>
                </div>
              )}

              <div className="flex justify-between items-center border-b border-[#2d3348] pb-2">
                <span className="text-gray-400">Failed Check:</span>
                <span className="text-amber-300 font-semibold">
                  {selectedItem.failed_check || selectedItem.reason}
                </span>
              </div>

              <div className="flex justify-between items-center border-b border-[#2d3348] pb-2">
                <span className="text-gray-400">Severity:</span>
                <StatusBadge status={selectedItem.severity || 'MEDIUM'} />
              </div>

              <div className="flex justify-between items-center border-b border-[#2d3348] pb-2">
                <span className="text-gray-400">Detected Format:</span>
                <span className="text-cyan-300 uppercase">
                  {selectedItem.detected_format || 'unknown'}
                </span>
              </div>

              <div className="flex justify-between items-center border-b border-[#2d3348] pb-2">
                <span className="text-gray-400">Status:</span>
                <StatusBadge status={selectedItem.status} />
              </div>

              <div className="flex flex-col gap-1 border-b border-[#2d3348] pb-2">
                <span className="text-gray-400">SHA-256 Hash (Lossless Vault Proof):</span>
                <span className="text-emerald-400 text-[11px] break-all bg-[#1a1f2e] p-1.5 rounded border border-[#2d3348]">
                  {selectedItem.raw_sha256 || 'Calculated in Evidence Vault'}
                </span>
              </div>

              <div className="flex flex-col gap-1">
                <span className="text-gray-400">Diagnostic Detail:</span>
                <p className="text-gray-300 bg-[#1a1f2e] p-2 rounded border border-[#2d3348]">
                  {selectedItem.detail}
                </p>
              </div>
            </div>

            {/* Verbatim Raw Message Preview */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-gray-400">
                <span className="flex items-center gap-1.5">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  VERBATIM RAW LOG EVIDENCE
                </span>
                <span className="text-[10px] text-gray-500">
                  {selectedItem.raw_message.length} bytes (Preserved Losslessly)
                </span>
              </div>
              <pre className="bg-[#0a0e1a] border border-[#2d3348] p-3 rounded-lg text-xs font-mono text-gray-200 overflow-x-auto whitespace-pre-wrap break-all max-h-40">
                {selectedItem.raw_message}
              </pre>
            </div>

            {/* Validation Failures / Metadata */}
            {selectedItem.validation_failures && selectedItem.validation_failures.length > 0 && (
              <div className="space-y-1">
                <h4 className="text-xs font-mono text-gray-400 font-semibold">
                  VALIDATION INVARIANTS VIOLATED:
                </h4>
                <ul className="list-disc list-inside text-xs text-red-300 font-mono bg-red-950/20 border border-red-900/40 p-3 rounded-lg space-y-1">
                  {selectedItem.validation_failures.map((f, i) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 pt-4 border-t border-[#2d3348]">
              <button
                onClick={() => setSelectedItem(null)}
                className="px-4 py-2 text-xs font-mono text-gray-400 hover:text-white bg-[#0a0e1a] border border-[#2d3348] rounded-lg transition"
              >
                CLOSE
              </button>
              <button
                onClick={() => handleAction(reprocessQuarantine, selectedItem.quarantine_id)}
                className="px-4 py-2 text-xs font-mono text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-700/60 rounded-lg transition"
              >
                REPROCESS EVENT
              </button>
              {selectedItem.status !== 'RELEASED' && (
                <button
                  onClick={() => handleAction(approveQuarantine, selectedItem.quarantine_id)}
                  className="px-4 py-2 text-xs font-mono text-emerald-300 bg-emerald-950/40 hover:bg-emerald-900/50 border border-emerald-700/60 rounded-lg transition"
                >
                  RELEASE TO PIPELINE
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
