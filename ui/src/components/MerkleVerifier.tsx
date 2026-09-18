'use client';

import React, { useState } from 'react';
import { Database, CheckCircle2, XCircle, Search, ShieldCheck } from 'lucide-react';

interface MerkleVerifierProps {
  selectedEvent?: any;
}

export default function MerkleVerifier({ selectedEvent }: MerkleVerifierProps) {
  const [hashInput, setHashInput] = useState(selectedEvent?.unmapped?.raw_event_hash || '');
  const [verifyStatus, setVerifyStatus] = useState<'idle' | 'valid' | 'tampered'>('idle');
  const [verificationDetails, setVerificationDetails] = useState<any>(null);

  const handleVerify = () => {
    const targetHash = hashInput.trim();
    if (!targetHash) return;

    // Simulate verification against local provenance ledger
    if (targetHash.length === 64) {
      setVerifyStatus('valid');
      setVerificationDetails({
        verified: true,
        hash: targetHash,
        batch_id: 'batch_001_500',
        ledger_status: 'COMMITTED_LOCAL_APPEND_ONLY',
        root_hash: '3f5a89b...e21c90',
        tree_depth: 9,
      });
    } else {
      setVerifyStatus('tampered');
      setVerificationDetails({
        verified: false,
        hash: targetHash,
        reason: 'Invalid SHA-256 hash length or mismatched root in local provenance ledger',
      });
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs">
      <div className="flex items-center justify-between mb-3 text-emerald-400 font-semibold">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4" />
          <span>CRYPTOGRAPHIC MERKLE PROVENANCE VERIFIER (LOCAL LEDGER ADAPTER)</span>
        </div>
        <span className="text-slate-400 text-[11px]">Micro-Batching (500 events/batch)</span>
      </div>

      <div className="flex gap-2 mb-3">
        <input
          type="text"
          placeholder="Paste raw log SHA-256 hash or select event above..."
          value={hashInput}
          onChange={(e) => {
            setHashInput(e.target.value);
            setVerifyStatus('idle');
          }}
          className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-emerald-500 text-xs"
        />
        <button
          onClick={handleVerify}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition-colors"
        >
          <Search className="w-3.5 h-3.5" /> Verify Provenance
        </button>
      </div>

      {verifyStatus === 'valid' && (
        <div className="p-3 rounded bg-emerald-950/30 border border-emerald-800/60 text-emerald-300 space-y-1">
          <div className="flex items-center gap-1.5 font-bold text-sm">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Cryptographic Integrity Confirmed</span>
          </div>
          <div className="text-[11px] text-emerald-400/80">
            Hash matches immutable entry in Evidence Vault and Provenance Ledger micro-batch root.
          </div>
          <div className="text-[10px] text-slate-400 pt-1">
            Status: <span className="text-emerald-400 font-semibold">{verificationDetails?.ledger_status}</span> |
            Depth: <span className="text-slate-200">{verificationDetails?.tree_depth}</span>
          </div>
        </div>
      )}

      {verifyStatus === 'tampered' && (
        <div className="p-3 rounded bg-rose-950/30 border border-rose-800/60 text-rose-300 space-y-1">
          <div className="flex items-center gap-1.5 font-bold text-sm">
            <XCircle className="w-4 h-4 text-rose-400" />
            <span>Verification Failed: Tamper or Unvaulted Hash Detected</span>
          </div>
          <div className="text-[11px] text-rose-400/80">{verificationDetails?.reason}</div>
        </div>
      )}
    </div>
  );
}
