import React from 'react';

export const MetricCard = ({ label, value, delta }: { label: string, value: string | number, delta?: string }) => (
  <div className="bg-[#1a1f2e] border border-[#2d3348] rounded-lg p-4 shadow-sm hover:border-[#06b6d4]/50 transition-colors">
    <div className="text-[#9ca3af] text-sm font-medium mb-1">{label}</div>
    <div className="text-2xl font-bold text-[#e5e7eb] flex items-baseline gap-2">
      {value}
      {delta && <span className="text-xs font-normal text-[#22c55e]">{delta}</span>}
    </div>
  </div>
);
