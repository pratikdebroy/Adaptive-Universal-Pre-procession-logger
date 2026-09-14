import React, { useState, useEffect } from 'react';
import { UploadCloud, CheckCircle2, AlertTriangle, ArrowRight, ShieldCheck, Zap } from 'lucide-react';
import { getOnboardingSamples, profileSource, promoteOnboardedParser, processEvent } from '../services/api';

export default function Onboarding() {
  const [sources, setSources] = useState<any[]>([]);
  const [selectedSource, setSelectedSource] = useState<string>('waf_perimeter');
  const [customSourceName, setCustomSourceName] = useState<string>('custom_device');
  const [sampleLogs, setSampleLogs] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [profileResult, setProfileResult] = useState<any>(null);
  const [promotionResult, setPromotionResult] = useState<any>(null);
  const [testLog, setTestLog] = useState<string>('');
  const [testResult, setTestResult] = useState<any>(null);

  useEffect(() => {
    getOnboardingSamples().then(res => {
      setSources(res.data.sources || []);
      if (res.data.sources?.length > 0) {
        setSelectedSource(res.data.sources[0].name);
        setSampleLogs(res.data.sources[0].samples.join('\n'));
      }
    }).catch(console.error);
  }, []);

  const handleSelectPreset = (src: any) => {
    setSelectedSource(src.name);
    setCustomSourceName(src.name);
    setSampleLogs(src.samples.join('\n'));
    setProfileResult(null);
    setPromotionResult(null);
    setTestResult(null);
  };

  const handleProfile = async () => {
    setLoading(true);
    setProfileResult(null);
    setPromotionResult(null);
    setTestResult(null);
    try {
      const logs = sampleLogs.split('\n').map(s => s.trim()).filter(Boolean);
      const res = await profileSource(customSourceName || selectedSource, logs);
      setProfileResult(res.data);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to profile log source');
    } finally {
      setLoading(false);
    }
  };

  const handlePromote = async () => {
    if (!profileResult?.candidate_id) return;
    setLoading(true);
    try {
      const res = await promoteOnboardedParser(profileResult.candidate_id);
      setPromotionResult(res.data);
      // Preload test log from samples
      const lines = sampleLogs.split('\n').filter(Boolean);
      if (lines.length > 0) {
        setTestLog(lines[0]);
      }
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to promote parser');
    } finally {
      setLoading(false);
    }
  };

  const handleTestEvent = async () => {
    if (!testLog) return;
    try {
      const res = await processEvent(testLog, customSourceName || selectedSource);
      setTestResult(res.data);
    } catch (err: any) {
      alert('Event test failed: ' + err.message);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#e5e7eb] flex items-center gap-2">
          <UploadCloud className="text-[#06b6d4]" />
          Plug-and-Play Log Source Onboarding
        </h1>
        <p className="text-sm text-[#9ca3af] mt-1">
          Zero-code onboarding: Profile sample logs → Discover template & OCSF mappings → Validate via Hybrid Trust Gate → Promote directly to Fast Path.
        </p>
      </div>

      {/* Preset Pickers */}
      <div className="flex gap-4">
        {sources.map(s => (
          <button
            key={s.name}
            onClick={() => handleSelectPreset(s)}
            className={`px-4 py-3 rounded-lg border text-left flex-1 transition-colors ${
              selectedSource === s.name ? 'border-[#06b6d4] bg-[#06b6d4]/10 text-[#e5e7eb]' : 'border-[#2d3348] bg-[#1a1f2e] text-[#9ca3af] hover:border-[#9ca3af]'
            }`}
          >
            <div className="font-semibold text-sm">{s.name}</div>
            <div className="text-xs text-[#9ca3af] mt-0.5">{s.description}</div>
          </button>
        ))}
      </div>

      {/* Input area */}
      <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold uppercase tracking-wider text-[#9ca3af]">Source Identifier</label>
          <input
            type="text"
            value={customSourceName}
            onChange={e => setCustomSourceName(e.target.value)}
            className="bg-[#0a0e1a] border border-[#2d3348] rounded px-3 py-1 text-sm font-mono text-[#06b6d4] w-64 focus:outline-none focus:border-[#06b6d4]"
          />
        </div>

        <div>
          <label className="text-xs font-semibold uppercase tracking-wider text-[#9ca3af] block mb-2">Sample Log Entries (1 per line)</label>
          <textarea
            rows={4}
            value={sampleLogs}
            onChange={e => setSampleLogs(e.target.value)}
            className="w-full bg-[#0a0e1a] border border-[#2d3348] rounded-lg p-3 text-xs font-mono text-[#e5e7eb] focus:outline-none focus:border-[#06b6d4]"
            placeholder="Paste raw log samples here..."
          />
        </div>

        <button
          onClick={handleProfile}
          disabled={loading || !sampleLogs.trim()}
          className="bg-[#06b6d4] hover:bg-[#0891b2] text-[#0a0e1a] font-semibold px-6 py-2.5 rounded-lg text-sm transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          <Zap size={18} />
          {loading ? 'Profiling Samples...' : 'Profile Source & Discover Template'}
        </button>
      </div>

      {/* Profiling Result Card */}
      {profileResult && (
        <div className="bg-[#1a1f2e] border border-[#06b6d4]/40 rounded-lg p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-[#2d3348] pb-4">
            <div>
              <span className="px-2.5 py-1 rounded bg-[#06b6d4]/20 border border-[#06b6d4]/40 text-[#06b6d4] text-xs font-mono font-semibold">
                {profileResult.status}
              </span>
              <h2 className="text-lg font-bold text-[#e5e7eb] mt-2">Discovered Specification for "{profileResult.source_name}"</h2>
            </div>
            <div className="text-right font-mono text-xs">
              <span className="text-[#9ca3af]">Confidence: </span>
              <span className="text-[#22c55e] font-bold">{(profileResult.confidence * 100).toFixed(0)}%</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-xs uppercase font-semibold text-[#9ca3af] mb-2">Discovered Template</h3>
              <div className="bg-[#0a0e1a] p-3 rounded border border-[#2d3348] font-mono text-xs text-[#06b6d4] break-all">
                {profileResult.discovered_template}
              </div>

              <h3 className="text-xs uppercase font-semibold text-[#9ca3af] mt-4 mb-2">Parser Safety Verification</h3>
              <div className="space-y-1">
                {profileResult.safety_checks?.checks?.map((c: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    {c.passed ? <CheckCircle2 size={14} className="text-[#22c55e]" /> : <AlertTriangle size={14} className="text-[#ef4444]" />}
                    <span className="text-[#e5e7eb] font-mono">{c.check_name}</span>
                    <span className="text-[#9ca3af]">{c.detail}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 className="text-xs uppercase font-semibold text-[#9ca3af] mb-2">Discovered OCSF Field Mappings</h3>
              <div className="bg-[#0a0e1a] p-3 rounded border border-[#2d3348] overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="text-[#9ca3af] border-b border-[#2d3348]">
                      <th className="text-left pb-1">Source Field</th>
                      <th className="text-left pb-1">OCSF Target</th>
                      <th className="text-left pb-1">Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(profileResult.mapped_fields || {}).map(([src, target]) => (
                      <tr key={src} className="border-b border-[#2d3348]/40">
                        <td className="py-1 text-[#06b6d4]">{src}</td>
                        <td className="py-1 text-[#22c55e]">{target as string}</td>
                        <td className="py-1 text-[#9ca3af]">{profileResult.field_types?.[src] || 'string'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {!promotionResult ? (
            <div className="border-t border-[#2d3348] pt-4 flex items-center justify-between">
              <span className="text-xs text-[#9ca3af]">Validated through Hybrid Trust Gate on {profileResult.sample_test_results?.length} samples.</span>
              <button
                onClick={handlePromote}
                className="bg-[#22c55e] hover:bg-[#16a34a] text-[#0a0e1a] font-bold px-6 py-2.5 rounded-lg text-sm transition-colors flex items-center gap-2"
              >
                <ShieldCheck size={18} />
                Approve & Promote to FAST PATH
              </button>
            </div>
          ) : (
            <div className="border-t border-[#2d3348] pt-4 space-y-4">
              <div className="bg-[#22c55e]/10 border border-[#22c55e]/30 rounded-lg p-4 flex items-center gap-3">
                <CheckCircle2 size={24} className="text-[#22c55e] shrink-0" />
                <div>
                  <h4 className="font-bold text-sm text-[#22c55e]">{promotionResult.status}</h4>
                  <p className="text-xs text-[#e5e7eb]">{promotionResult.message}</p>
                </div>
              </div>

              {/* Live fast path verification */}
              <div className="bg-[#0a0e1a] p-4 rounded-lg border border-[#2d3348] space-y-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-[#9ca3af]">Verify Fast-Path Processing for New Source</div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={testLog}
                    onChange={e => setTestLog(e.target.value)}
                    className="flex-1 bg-[#1a1f2e] border border-[#2d3348] rounded px-3 py-1.5 text-xs font-mono text-[#e5e7eb]"
                  />
                  <button
                    onClick={handleTestEvent}
                    className="bg-[#06b6d4] hover:bg-[#0891b2] text-[#0a0e1a] font-bold px-4 py-1.5 rounded text-xs"
                  >
                    Send Event
                  </button>
                </div>

                {testResult && (
                  <div className="bg-[#1a1f2e] p-3 rounded border border-[#2d3348] text-xs font-mono space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[#9ca3af]">Processing Mode:</span>
                      <span className="px-2 py-0.5 rounded bg-[#06b6d4]/20 text-[#06b6d4] font-bold">{testResult.processing_mode}</span>
                      <span className="text-[#22c55e]">(Promoted parser successfully matched on Fast Path!)</span>
                    </div>
                    <div><span className="text-[#9ca3af]">Confidence:</span> {(testResult.confidence * 100).toFixed(0)}%</div>
                    <div><span className="text-[#9ca3af]">Raw SHA-256:</span> {testResult.raw_sha256}</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
