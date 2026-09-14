import React from 'react';

export const StatusBadge = ({ status }: { status: string }) => {
  const getColors = () => {
    switch (status) {
      case 'FAST_PATH':
        return 'bg-[#06b6d4]/10 text-[#06b6d4] border-[#06b6d4]/30 shadow-[0_0_8px_rgba(6,182,212,0.2)]';
      case 'STRUCTURAL':
        return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30 shadow-[0_0_8px_rgba(245,158,11,0.2)]';
      case 'TIER3':
      case 'TIER3_ADAPTIVE':
        return 'bg-[#ef4444]/10 text-[#ef4444] border-[#ef4444]/30 shadow-[0_0_8px_rgba(239,68,68,0.2)]';
      case 'APPROVED':
      case 'ACTIVE':
      case 'RELEASED':
        return 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30 shadow-[0_0_8px_rgba(34,197,94,0.2)]';
      case 'REVIEWED':
        return 'bg-[#06b6d4]/10 text-[#06b6d4] border-[#06b6d4]/30';
      case 'DISCARDED':
        return 'bg-gray-800 text-gray-500 border-gray-700 line-through';
      case 'CANDIDATE':
        return 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/30';
      case 'QUARANTINED':
      case 'ROLLED_BACK':
        return 'bg-[#ef4444]/10 text-[#ef4444] border-[#ef4444]/30';
      // Severity badges
      case 'CRITICAL':
        return 'bg-purple-950/50 text-purple-400 border-purple-700/60 font-bold';
      case 'HIGH':
        return 'bg-red-950/50 text-red-400 border-red-700/60 font-semibold';
      case 'MEDIUM':
        return 'bg-amber-950/50 text-amber-400 border-amber-700/60';
      case 'LOW':
        return 'bg-blue-950/50 text-blue-400 border-blue-700/60';
      default:
        // For quarantine reasons (e.g. INVALID_IP, MALFORMED_JSON, etc.)
        if (status.includes('INVALID') || status.includes('MALFORMED') || status.includes('UNSAFE') || status.includes('ERROR') || status.includes('EXCESSIVE')) {
          return 'bg-red-950/40 text-red-300 border-red-800/50';
        }
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  return (
    <span className={`px-2 py-0.5 text-xs font-mono rounded border ${getColors()} inline-block`}>
      {status.replace(/_/g, ' ')}
    </span>
  );
};
