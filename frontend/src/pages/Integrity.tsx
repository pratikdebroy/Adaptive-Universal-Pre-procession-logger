import React, { useState, useEffect } from 'react';
import { getEvents, verifyIntegrity, commitToLedger, getLedger, tamperDemo } from '../services/api';

export default function Integrity() {
  const [events, setEvents] = useState<any[]>([]);
  const [ledger, setLedger] = useState<any[]>([]);
  const [verifyResult, setVerifyResult] = useState<any>(null);

  const fetchData = () => {
    getEvents(10).then(res => setEvents(res.data?.events || [])).catch(console.error);
    getLedger().then(res => setLedger(res.data?.entries || [])).catch(console.error);
  };

  useEffect(() => { fetchData(); }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Evidence & Integrity</h1>
        <div className="text-sm text-[#9ca3af] bg-[#1a1f2e] px-4 py-2 rounded-lg border border-[#2d3348]">
          Prototype Permissioned-Ledger Adapter
        </div>
      </div>
      
      <div className="flex gap-4">
        <button onClick={() => verifyIntegrity().then(res => setVerifyResult(res.data))} className="bg-[#14b8a6] hover:bg-[#14b8a6]/80 text-[#0a0e1a] font-semibold px-4 py-2 rounded">VERIFY INTEGRITY</button>
        <button onClick={() => commitToLedger().then(fetchData)} className="bg-[#06b6d4] hover:bg-[#06b6d4]/80 text-[#0a0e1a] font-semibold px-4 py-2 rounded">COMMIT TO LEDGER</button>
        <button onClick={() => tamperDemo().then(() => verifyIntegrity().then(res => setVerifyResult(res.data)))} className="bg-[#ef4444] hover:bg-[#ef4444]/80 text-[#0a0e1a] font-semibold px-4 py-2 rounded">SIMULATE TAMPER</button>
      </div>

      {verifyResult && (
        <div className={`p-4 rounded-lg border ${verifyResult.integrity_status === 'VERIFIED' ? 'bg-[#22c55e]/10 border-[#22c55e]/30 text-[#22c55e]' : 'bg-[#ef4444]/10 border-[#ef4444]/30 text-[#ef4444]'}`}>
          <h3 className="font-bold">{verifyResult.integrity_status === 'VERIFIED' ? 'MERKLE TREE VERIFIED' : 'INTEGRITY FAILURE'}</h3>
          <p className="text-sm mt-1 font-mono">Computed Root: {verifyResult.computed_root?.substring(0,32)}...</p>
          {verifyResult.tampered_events?.length > 0 && <p className="text-sm mt-1">Tampered events: {verifyResult.tampered_events.join(', ')}</p>}
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-4 space-y-4">
          <h3 className="font-semibold text-[#e5e7eb]">Provenance Chain</h3>
          {events.map((evt: any, i: number) => (
            <div key={i} className="bg-[#0a0e1a] border border-[#2d3348] rounded p-3 text-xs space-y-2">
              <div className="flex items-center gap-2 text-[#9ca3af]">RAW EVENT → <span className="font-mono text-[#06b6d4]">{(evt.raw_sha256 || evt.hash || '').substring(0,16)}...</span> → PARSER v{evt.parser_version || '1'} → NORMALIZED (OCSF)</div>
              <div className="font-mono truncate">{evt.raw_message}</div>
            </div>
          ))}
          {events.length === 0 && <div className="text-sm text-[#9ca3af]">No events processed yet</div>}
        </div>
        <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-4 space-y-4">
          <h3 className="font-semibold text-[#e5e7eb]">Ledger Entries</h3>
          {ledger.map((entry: any, i: number) => (
            <div key={i} className="bg-[#0a0e1a] border border-[#2d3348] rounded p-3 text-xs space-y-1">
              <div className="flex justify-between text-[#9ca3af]"><span>Block #{entry.batch_id?.substring(0,8)}</span> <span>{new Date(entry.timestamp).toLocaleString()}</span></div>
              <div className="font-mono text-[#14b8a6]">Root: {entry.merkle_root?.substring(0,32)}...</div>
              <div>Events: {entry.event_count}</div>
            </div>
          ))}
          {ledger.length === 0 && <div className="text-sm text-[#9ca3af]">No ledger blocks committed</div>}
        </div>
      </div>
    </div>
  );
}
