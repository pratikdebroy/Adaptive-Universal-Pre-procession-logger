import React, { useState, useEffect } from 'react';
import { runBenchmark, getBenchmarkResults } from '../services/api';
import { MetricCard } from '../components/MetricCard';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const COLORS = ['#06b6d4', '#f59e0b', '#ef4444'];

export default function Benchmarks() {
  const [results, setResults] = useState<any>(null);
  const [running, setRunning] = useState(false);
  const [count, setCount] = useState(100);

  const fetchR = () => getBenchmarkResults().then(res => setResults(res.data)).catch(console.error);
  useEffect(() => { fetchR(); }, []);

  const handleRun = () => {
    setRunning(true);
    runBenchmark(count).then(res => {
      setResults(res.data);
      setRunning(false);
    }).catch(() => setRunning(false));
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">Benchmarks</h1>
          <p className="text-sm text-[#9ca3af] mt-1">Prototype benchmark — local environment</p>
        </div>
        <div className="flex gap-4 items-center">
          <select value={count} onChange={e => setCount(Number(e.target.value))} className="bg-[#1a1f2e] border border-[#2d3348] rounded px-3 py-2 text-sm focus:outline-none">
            <option value={100}>100 Events</option>
            <option value={1000}>1,000 Events</option>
            <option value={10000}>10,000 Events</option>
          </select>
          <button onClick={handleRun} disabled={running} className="bg-[#06b6d4] hover:bg-[#06b6d4]/80 disabled:opacity-50 text-[#0a0e1a] font-semibold px-4 py-2 rounded">
            {running ? 'RUNNING...' : 'RUN BENCHMARK'}
          </button>
        </div>
      </div>

      {results && (
        <>
          <div className="grid grid-cols-4 gap-4">
            <MetricCard label="Total Events" value={results.total_events} />
            <MetricCard label="Events/sec" value={results.events_per_second?.toFixed(2)} />
            <MetricCard label="Avg Latency" value={`${results.avg_latency_ms?.toFixed(2)} ms`} />
            <MetricCard label="P95 Latency" value={`${results.p95_latency_ms?.toFixed(2)} ms`} />
          </div>
          
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-6">
              <h3 className="font-semibold text-[#e5e7eb] mb-4">Event Distribution</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[
                    { name: 'Known', count: results.known_events },
                    { name: 'Drifted', count: results.drifted_events },
                    { name: 'Malformed', count: results.malformed_events }
                  ]}>
                    <XAxis dataKey="name" stroke="#9ca3af" fontSize={12} />
                    <YAxis stroke="#9ca3af" fontSize={12} />
                    <Tooltip cursor={{fill: '#2d3348'}} contentStyle={{backgroundColor: '#1a1f2e', borderColor: '#2d3348'}} />
                    <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-6 flex flex-col items-center">
              <h3 className="font-semibold text-[#e5e7eb] mb-4 self-start">Processing Mode Breakdown</h3>
              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={[
                      { name: 'Fast Path', value: results.known_events || 0 },
                      { name: 'Structural', value: (results.drifted_events || 0) - (results.tier3_invocation_count || 0) },
                      { name: 'Tier-3', value: results.tier3_invocation_count || 0 }
                    ]} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                      {COLORS.map((color, i) => <Cell key={i} fill={color} />)}
                    </Pie>
                    <Tooltip contentStyle={{backgroundColor: '#1a1f2e', borderColor: '#2d3348'}} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex gap-4 mt-4 text-sm">
                <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#06b6d4]"></span>Fast Path</div>
                <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#f59e0b]"></span>Structural</div>
                <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#ef4444]"></span>Tier-3</div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-4 gap-4">
            <MetricCard label="Parsing Accuracy" value={`${(results.parsing_accuracy || 0).toFixed(1)}%`} />
            <MetricCard label="Schema Validity" value={`${(results.schema_validity_rate || 0).toFixed(1)}%`} />
            <MetricCard label="Quarantine Rate" value={`${(results.quarantine_rate || 0).toFixed(1)}%`} />
            <MetricCard label="Recovery Rate" value={`${(results.recovery_rate || 0).toFixed(1)}%`} />
          </div>

          <div className="bg-[#1a1f2e] border border-[#ef4444]/30 rounded-lg p-6 text-center">
            <div className="text-3xl font-bold text-[#ef4444] mb-2">Tier-3 Invocation Rate: {((results.tier3_count / (results.total_events || 1)) * 100).toFixed(1)}%</div>
            <p className="text-[#9ca3af] text-sm">Percentage of events requiring local SLM + RAG processing</p>
          </div>
        </>
      )}
    </div>
  );
}
