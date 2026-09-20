import React, { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { Activity, Cpu, Database, ShieldAlert, ShieldCheck, BarChart2, PlayCircle, UploadCloud, Menu, X } from "lucide-react";
import LivePipeline from "./pages/LivePipeline";
import AdaptiveParser from "./pages/AdaptiveParser";
import ParserRegistry from "./pages/ParserRegistry";
import Quarantine from "./pages/Quarantine";
import Integrity from "./pages/Integrity";
import Benchmarks from "./pages/Benchmarks";
import JudgeDemo from "./pages/JudgeDemo";
import Onboarding from "./pages/Onboarding";
import { getHealth } from "./services/api";

const NavItem = ({ to, icon: Icon, label, onClick }: { to: string, icon: any, label: string, onClick?: () => void }) => {
  const location = useLocation();
  const isActive = location.pathname === to;
  return (
    <Link 
      to={to} 
      onClick={onClick}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? "bg-[#1a1f2e] text-[#06b6d4] border border-[#2d3348]" : "text-[#9ca3af] hover:text-[#e5e7eb] hover:bg-[#1a1f2e]"}`}
    >
      <Icon size={20} />
      <span className="font-medium text-sm">{label}</span>
    </Link>
  );
};

export default function App() {
  const [health, setHealth] = useState({ status: "unknown", inference_mode: "...", parsers_loaded: 0 });
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  useEffect(() => {
    getHealth().then(res => setHealth(res.data)).catch(console.error);
    const interval = setInterval(() => {
      getHealth().then(res => setHealth(res.data)).catch(console.error);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const isHealthy = health.status === "healthy" || health.status === "ok";
  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);
  const closeSidebar = () => setIsSidebarOpen(false);

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-[#0a0e1a] text-[#e5e7eb] overflow-hidden">
        
        {/* Mobile Overlay */}
        {isSidebarOpen && (
          <div 
            className="fixed inset-0 bg-black/60 z-40 lg:hidden"
            onClick={closeSidebar}
          />
        )}

        {/* Sidebar */}
        <aside className={`fixed lg:static inset-y-0 left-0 z-50 w-64 bg-[#0a0e1a] border-r border-[#2d3348] flex flex-col transition-transform duration-300 ease-in-out ${isSidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}>
          <div className="p-6 border-b border-[#2d3348] flex items-center justify-between lg:block">
            <div>
              <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-[#06b6d4] to-[#14b8a6]">PORT 8080</h1>
              <p className="text-xs text-[#9ca3af] mt-1 font-mono">SIH26156 - NTRO Framework</p>
            </div>
            <button className="lg:hidden text-[#9ca3af] hover:text-white" onClick={closeSidebar}>
              <X size={24} />
            </button>
          </div>
          <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
            <NavItem to="/demo" icon={PlayCircle} label="JUDGE DEMO" onClick={closeSidebar} />
            <NavItem to="/" icon={Activity} label="LIVE PIPELINE" onClick={closeSidebar} />
            <NavItem to="/onboarding" icon={UploadCloud} label="SOURCE ONBOARDING" onClick={closeSidebar} />
            <NavItem to="/registry" icon={Database} label="PARSER REGISTRY" onClick={closeSidebar} />
            <NavItem to="/quarantine" icon={ShieldAlert} label="QUARANTINE (DLQ)" onClick={closeSidebar} />
            <NavItem to="/integrity" icon={ShieldCheck} label="EVIDENCE & INTEGRITY" onClick={closeSidebar} />
            <NavItem to="/benchmarks" icon={BarChart2} label="BENCHMARKS" onClick={closeSidebar} />
          </nav>
          <div className="p-4 border-t border-[#2d3348] bg-[#0a0e1a] text-center space-y-1.5 hidden sm:block">
            <p className="text-[10px] font-mono text-[#06b6d4] uppercase tracking-wider font-semibold">
              Preserve   Detect   Adapt   Trust   Reuse
            </p>
            <p className="text-[9px] font-mono text-[#9ca3af] uppercase tracking-wider">
              AI PROPOSES - TRUST GATE DECIDES - LEDGER PROVES
            </p>
          </div>
        </aside>
        
        <main className="flex-1 flex flex-col h-full overflow-hidden w-full">
          <header className="h-auto min-h-[64px] border-b border-[#2d3348] flex flex-col sm:flex-row items-start sm:items-center justify-between px-4 sm:px-6 py-4 sm:py-0 shrink-0 bg-[#0a0e1a]/80 backdrop-blur gap-4 sm:gap-0">
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <button className="lg:hidden text-[#9ca3af] hover:text-white shrink-0" onClick={toggleSidebar}>
                <Menu size={24} />
              </button>
              <h2 className="text-sm sm:text-base font-semibold text-[#e5e7eb] truncate">Universal Log Pre-processing Framework</h2>
            </div>
            <div className="flex flex-wrap items-center gap-3 sm:gap-5 text-xs sm:text-sm">
              <div className="flex items-center gap-2">
                <span className="text-[#9ca3af] hidden md:inline">AI Inference:</span>
                <span className="px-2 py-1 rounded bg-[#1a1f2e] border border-[#2d3348] text-[#06b6d4] font-mono text-[10px] sm:text-xs font-semibold truncate max-w-[120px] sm:max-w-none">{health.inference_mode}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#9ca3af] hidden md:inline">Active:</span>
                <span className="font-mono text-[10px] sm:text-xs px-2 py-0.5 rounded bg-[#1a1f2e] border border-[#2d3348] text-[#22c55e]">{health.parsers_loaded}</span>
              </div>
              <div className="flex items-center gap-2 ml-auto sm:ml-0">
                <span className={`w-2 h-2 sm:w-2.5 sm:h-2.5 rounded-full ${isHealthy ? "bg-[#22c55e] shadow-[0_0_8px_rgba(34,197,94,0.6)]" : "bg-[#ef4444]"}`}></span>
                <span className="capitalize font-medium hidden sm:inline">{health.status}</span>
              </div>
            </div>
          </header>
          <div className="flex-1 overflow-auto p-4 sm:p-6 relative">
            <Routes>
              <Route path="/" element={<LivePipeline />} />
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
