import React, { useState, useEffect } from 'react';
import { Play, RotateCcw, CheckCircle2, ShieldCheck, Cpu, Database, AlertTriangle, ArrowRight } from 'lucide-react';
import { executeDemoStep, resetDemo, getDemoState } from '../services/api';

const demoStepMeta = [
  { step: 1, name: "KNOWN FORMAT", desc: "Firewall emits standard known format (SRC=... DST=...). Expected: Handled immediately by FAST PATH with 0 AI invocation." },
  { step: 2, name: "INTRODUCE DRIFT", desc: "Firewall vendor updates format to (SRC_IP=... DST_IP=...). Expected: Old parser misses, format signature mismatch." },
  { step: 3, name: "ADAPT", desc: "Engine initiates Tier-2 Structural Analysis, then invokes Tier-3 Adaptive inference (Demo Fallback / Local SLM)." },
  { step: 4, name: "CANDIDATE PARSER", desc: "System synthesizes a structured Parser Specification (JSON) without generating executable code." },
  { step: 5, name: "TRUST GATE", desc: "Hybrid Trust Gate verifies candidate parser safety and executes test checks: IP, Port, Protocol, Action, Plausibility." },
  { step: 6, name: "PARSER PROMOTION", desc: "Atomic promotion: Parser written to persistent SQLite ledger and activated in-memory cache." },
  { step: 7, name: "REPLAY (FAST PATH)", desc: "Replay the drifted format log. Expected: Handled by FAST PATH! Self-healing proven with ZERO AI invocation." },
  { step: 8, name: "SHOW PROVENANCE", desc: "Traceability audit: Inspect Raw Event → SHA-256 → Active Parser Version → OCSF Network Activity." },
  { step: 9, name: "TEST TAMPER", desc: "Simulate forensic tamper in Evidence Vault. Merkle verification detects hash discrepancy and reports INTEGRITY FAILURE." },
];

export default function JudgeDemo() {
  const [demoState, setDemoState] = useState<any>(null);
  const [lastResult, setLastResult] = useState<any>(null);
  const [loadingStep, setLoadingStep] = useState<number | null>(null);

  const fetchState = async () => {
    try {
      const res = await getDemoState();
      setDemoState(res.data);
      if (res.data?.last_response) {
        setLastResult(res.data.last_response);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchState();
  }, []);

  const handleStep = async (stepNum: number) => {
    setLoadingStep(stepNum);
    try {
      const res = await executeDemoStep(stepNum);
      setLastResult(res.data);
      await fetchState();
    } catch (err: any) {
      alert('Error executing step ' + stepNum + ': ' + (err.response?.data?.detail || err.message));
    } finally {
      setLoadingStep(null);
    }
  };

  const handleReset = async () => {
    setLoadingStep(-1);
    try {
      await resetDemo();
      setLastResult(null);
      await fetchState();
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingStep(null);
    }
  };

  const currentStep = demoState?.current_step || 0;
  const completedSteps = demoState?.completed_steps || [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex justify-between items-center bg-[#1a1f2e] border border-[#2d3348] p-5 rounded-lg">
        <div>
          <h1 className="text-2xl font-bold text-[#e5e7eb] flex items-center gap-3">
            <Play className="text-[#06b6d4]" />
            Official SIH Judge Live Demonstration
          </h1>
          <p className="text-xs text-[#9ca3af] mt-1">
            Deterministic when known · Adaptive when unknown · Verified before trust · Learned parsers return to fast path.
          </p>
        </div>
        <button
          onClick={handleReset}
          disabled={loadingStep !== null}
          className="flex items-center gap-2 text-xs font-semibold bg-[#ef4444]/10 hover:bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30 px-4 py-2 rounded transition-colors disabled:opacity-50"
        >
          <RotateCcw size={14} />
          RESET DEMO STATE
        </button>
      </div>

      {/* 5 Core Pillars Banner */}
      <div className="flex items-center justify-between gap-3 bg-[#0a0e1a] border border-[#2d3348] px-4 py-2.5 rounded-lg text-xs font-mono">
        <span className="text-[#9ca3af] font-semibold">Core Architectural Cycle:</span>
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded bg-[#06b6d4]/15 text-[#06b6d4] border border-[#06b6d4]/30 font-bold">1. Preserve</span>
          <ArrowRight size={12} className="text-[#9ca3af]" />
          <span className="px-2.5 py-1 rounded bg-[#f59e0b]/15 text-[#f59e0b] border border-[#f59e0b]/30 font-bold">2. Detect</span>
          <ArrowRight size={12} className="text-[#9ca3af]" />
          <span className="px-2.5 py-1 rounded bg-[#a855f7]/15 text-[#a855f7] border border-[#a855f7]/30 font-bold">3. Adapt</span>
          <ArrowRight size={12} className="text-[#9ca3af]" />
          <span className="px-2.5 py-1 rounded bg-[#22c55e]/15 text-[#22c55e] border border-[#22c55e]/30 font-bold">4. Trust</span>
          <ArrowRight size={12} className="text-[#9ca3af]" />
          <span className="px-2.5 py-1 rounded bg-[#06b6d4]/15 text-[#06b6d4] border border-[#06b6d4]/30 font-bold">5. Reuse</span>
        </div>
      </div>

      {/* Stepper Timeline */}
      <div className="grid grid-cols-3 lg:grid-cols-9 gap-2">
        {demoStepMeta.map((s) => {
          const isDone = completedSteps.includes(s.step);
          const isCurrent = currentStep === s.step;
          const isLoading = loadingStep === s.step;

          return (
            <button
              key={s.step}
              onClick={() => handleStep(s.step)}
              disabled={loadingStep !== null}
              className={`p-3 rounded-lg border text-left flex flex-col justify-between min-h-[90px] transition-all ${
                isCurrent
                  ? 'bg-[#06b6d4]/15 border-[#06b6d4] text-[#06b6d4] shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                  : isDone
                  ? 'bg-[#22c55e]/10 border-[#22c55e]/40 text-[#22c55e]'
                  : 'bg-[#1a1f2e] border-[#2d3348] text-[#9ca3af] hover:border-[#9ca3af]'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold">STEP {s.step}</span>
                {isDone && <CheckCircle2 size={14} className="text-[#22c55e]" />}
              </div>
              <div className="text-xs font-semibold uppercase leading-tight line-clamp-2">
                {isLoading ? 'Running...' : s.name}
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Step Content / Detailed Output */}
      {lastResult ? (
        <div className="bg-[#1a1f2e] border border-[#06b6d4]/40 rounded-lg p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-[#2d3348] pb-4">
            <div>
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-[#06b6d4]/20 text-[#06b6d4] border border-[#06b6d4]/30 font-bold">
                STEP {lastResult.step} OF 9
              </span>
              <h2 className="text-xl font-bold text-[#e5e7eb] mt-2">{lastResult.title}</h2>
              <p className="text-xs text-[#9ca3af] mt-1">{lastResult.description}</p>
            </div>
            {lastResult.highlight?.path && (
              <div className="text-right">
                <span className="text-xs text-[#9ca3af] block">Routing Path:</span>
                <span className={`px-3 py-1 rounded text-xs font-mono font-bold ${
                  lastResult.highlight.path === 'FAST_PATH' ? 'bg-[#06b6d4]/20 text-[#06b6d4] border border-[#06b6d4]/40' :
                  lastResult.highlight.path === 'STRUCTURAL' ? 'bg-[#f59e0b]/20 text-[#f59e0b] border border-[#f59e0b]/40' :
                  'bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/40'
                }`}>
                  {lastResult.highlight.path}
                </span>
              </div>
            )}
          </div>

          {/* Highlight Banner */}
          {lastResult.highlight && (
            <div className="bg-[#0a0e1a] border border-[#2d3348] p-4 rounded-lg flex items-center justify-between font-mono text-xs">
              <div className="space-y-1">
                {lastResult.highlight.message && (
                  <div className="text-[#22c55e] font-bold text-sm flex items-center gap-2">
                    <CheckCircle2 size={16} />
                    {lastResult.highlight.message}
                  </div>
                )}
                {lastResult.highlight.reason && (
                  <div className="text-[#f59e0b] flex items-center gap-2">
                    <AlertTriangle size={16} />
                    {lastResult.highlight.reason}
                  </div>
                )}
                {lastResult.highlight.tier_detail && (
                  <div className="text-[#9ca3af]">{lastResult.highlight.tier_detail}</div>
                )}
              </div>

              {lastResult.highlight.tier3_invocations_this_event !== undefined && (
                <div className="text-right">
                  <div className="text-[#9ca3af]">Tier-3 Invocations For This Replay:</div>
                  <div className="text-[#22c55e] text-lg font-bold">
                    {lastResult.highlight.tier3_invocations_this_event} (Zero AI Overhead!)
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Trust Gate Details if present */}
          {lastResult.validation_checks && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#9ca3af]">
                Hybrid Trust Gate Invariant Checks
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {lastResult.validation_checks.map((chk: any, idx: number) => (
                  <div key={idx} className="bg-[#0a0e1a] p-3 rounded border border-[#2d3348] flex items-start gap-2 text-xs">
                    {chk.passed ? <CheckCircle2 size={16} className="text-[#22c55e] shrink-0 mt-0.5" /> : <AlertTriangle size={16} className="text-[#ef4444] shrink-0 mt-0.5" />}
                    <div>
                      <div className="font-mono text-[#e5e7eb] font-semibold">{chk.check_name}</div>
                      <div className="text-[#9ca3af] text-[11px] mt-0.5">{chk.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tamper / Integrity Proof if present */}
          {lastResult.integrity && (
            <div className="bg-[#0a0e1a] p-4 rounded border border-[#ef4444]/40 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[#9ca3af]">Forensic Integrity Status:</span>
                <span className={`px-2 py-0.5 rounded font-bold ${lastResult.integrity.status === 'FAILURE' ? 'bg-[#ef4444]/20 text-[#ef4444]' : 'bg-[#22c55e]/20 text-[#22c55e]'}`}>
                  {lastResult.integrity.status === 'FAILURE' ? 'TAMPER DETECTED — MERKLE ROOT MISMATCH' : 'INTEGRITY VERIFIED'}
                </span>
              </div>
              <div><span className="text-[#9ca3af]">Expected Ledger Merkle Root :</span> {lastResult.integrity.expected_merkle_root}</div>
              <div><span className="text-[#9ca3af]">Recomputed Raw Evidence Root :</span> <span className="text-[#ef4444]">{lastResult.integrity.computed_merkle_root}</span></div>
              <div><span className="text-[#9ca3af]">Tampered Event Identifiers    :</span> <span className="text-[#f59e0b]">{JSON.stringify(lastResult.integrity.tampered_events)}</span></div>
            </div>
          )}

          {/* Expandable JSON Inspector */}
          <details className="text-xs bg-[#0a0e1a] border border-[#2d3348] rounded p-3">
            <summary className="font-mono text-[#9ca3af] cursor-pointer hover:text-[#06b6d4]">
              Inspect Raw Machine Payload (JSON)
            </summary>
            <pre className="mt-3 font-mono text-[#06b6d4] overflow-x-auto p-2 bg-[#111827] rounded">
              {JSON.stringify(lastResult, null, 2)}
            </pre>
          </details>
        </div>
      ) : (
        <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-12 text-center text-[#9ca3af]">
          <Play size={48} className="mx-auto text-[#06b6d4] opacity-50 mb-3" />
          <p className="font-semibold text-[#e5e7eb]">Click "STEP 1. KNOWN FORMAT" to initiate the 9-step evaluation demo.</p>
          <p className="text-xs mt-1">Each step triggers an authentic backend pipeline state transition without mocks.</p>
        </div>
      )}

      {/* Footer Mantra */}
      <div className="bg-[#0a0e1a] border border-[#06b6d4]/30 rounded-lg p-3 text-center">
        <p className="font-mono text-[#06b6d4] text-xs tracking-wider">
          AI PROPOSES · TRUST GATE DECIDES · LEDGER PROVES
        </p>
      </div>
    </div>
  );
}
