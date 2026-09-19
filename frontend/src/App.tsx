import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom';
import { Activity, Cpu, Database, ShieldAlert, ShieldCheck, BarChart2, PlayCircle, UploadCloud } from 'lucide-react';
import LivePipeline from './pages/LivePipeline';
import AdaptiveParser from './pages/AdaptiveParser';
import ParserRegistry from './pages/ParserRegistry';
import Quarantine from './pages/Quarantine';
import Integrity from './pages/Integrity';
import Benchmarks from './pages/Benchmarks';
import JudgeDemo from './pages/JudgeDemo';
import Onboarding from './pages/Onboarding';
import { getHealth } from './services/api';

const NavItem = ({ to, icon: Icon, label }: { to: string, icon: any, label: string }) => {
  const location = useLocation();
  const isActive = location.pathname === to;
  return (
    <Link to={to} className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? 'bg-[#1a1f2e] text-[#06b6d4] border border-[#2d3348]' : 'text-[#9ca3af] hover:text-[#e5e7eb] hover:bg-[#1a1f2e]'}`}>
      <Icon size={20} />
      <span className="font-medium text-sm">{label}</span>
    </Link>
  );
};

export default function App() {
  const [health, setHealth] = useState({ status: 'unknown', inference_mode: '...', parsers_loaded: 0 });

  useEffect(() => {
    getHealth().then(res => setHealth(res.data)).catch(console.error);
    const interval = setInterval(() => {
      getHealth().then(res => setHealth(res.data)).catch(console.error);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const isHealthy = health.status === 'healthy' || health.status === 'ok';

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-[#0a0e1a] text-[#e5e7eb] overflow-hidden">
        <aside className="w-64 border-r border-[#2d3348] flex flex-col">
          <div className="p-6 border-b border-[#2d3348]">
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-[#06b6d4] to-[#14b8a6]">PORT 8080</h1>
            <p className="text-xs text-[#9ca3af] mt-1 font-mono">SIH26156 — NTRO Framework</p>
          </div>
          <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
            <NavItem to="/demo" icon={PlayCircle} label="JUDGE DEMO" />
            <NavItem to="/" icon={Activity} label="LIVE PIPELINE" />
            <NavItem to="/adaptive" icon={Cpu} label="ADAPTIVE PARSER" />
            <NavItem to="/onboarding" icon={UploadCloud} label="SOURCE ONBOARDING" />
            <NavItem to="/registry" icon={Database} label="PARSER REGISTRY" />
            <NavItem to="/quarantine" icon={ShieldAlert} label="QUARANTINE (DLQ)" />
            <NavItem to="/integrity" icon={ShieldCheck} label="EVIDENCE & INTEGRITY" />
            <NavItem to="/benchmarks" icon={BarChart2} label="BENCHMARKS" />
          </nav>
          <div className="p-4 border-t border-[#2d3348] bg-[#0a0e1a] text-center space-y-1.5">
            <p className="text-[10px] font-mono text-[#06b6d4] uppercase tracking-wider font-semibold">
              Preserve → Detect → Adapt → Trust → Reuse
            </p>
            <p className="text-[9px] font-mono text-[#9ca3af] uppercase tracking-wider">
              AI PROPOSES · TRUST GATE DECIDES · LEDGER PROVES
            </p>
          </div>
        </aside>
        
        <main className="flex-1 flex flex-col h-full overflow-hidden">
          <header className="h-16 border-b border-[#2d3348] flex items-center justify-between px-6 shrink-0 bg-[#0a0e1a]/80 backdrop-blur">
            <h2 className="text-base font-semibold text-[#e5e7eb]">Universal Log Pre-processing Framework</h2>
            <div className="flex items-center gap-5 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-[#9ca3af] text-xs">AI Inference Mode:</span>
                <span className="px-2.5 py-1 rounded bg-[#1a1f2e] border border-[#2d3348] text-[#06b6d4] font-mono text-xs font-semibold">{health.inference_mode}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#9ca3af] text-xs">Active Parsers:</span>
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#1a1f2e] border border-[#2d3348] text-[#22c55e]">{health.parsers_loaded}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${isHealthy ? 'bg-[#22c55e] shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-[#ef4444]'}`}></span>
                <span className="capitalize text-xs font-medium">{health.status}</span>
              </div>
            </div>
          </header>
          <div className="flex-1 overflow-auto p-6 relative">
            <Routes>
              <Route path="/" element={<LivePipeline />} />
              <Route path="/adaptive" element={<AdaptiveParser />} />
              <Route path="/onboarding" element={<Onboarding />} />
              <Route path="/registry" element={<ParserRegistry />} />
              <Route path="/quarantine" element={<Quarantine />} />
              <Route path="/integrity" element={<Integrity />} />
              <Route path="/benchmarks" element={<Benchmarks />} />
              <Route path="/demo" element={<JudgeDemo />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}
