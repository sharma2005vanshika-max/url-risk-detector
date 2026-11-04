import React from 'react';
import { History, Trash2, ArrowUpRight } from 'lucide-react';
import { ScanResult } from '../types';

interface ThreatHistoryProps {
  history: ScanResult[];
  onSelectResult: (res: ScanResult) => void;
  onClearHistory: () => void;
}

export const ThreatHistory: React.FC<ThreatHistoryProps> = ({ history, onSelectResult, onClearHistory }) => {
  if (history.length === 0) {
    return (
      <div className="p-12 text-center rounded-2xl bg-cyber-900 border border-cyber-border">
        <History className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h4 className="text-sm font-bold font-mono text-slate-300">No Scans Recorded Yet</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          Scan URLs in the URL Scanner or Batch Scanner to automatically compile an audit trail of threat assessments.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            Security Audit Trail ({history.length})
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Locally cached URL risk assessments from this session.
          </p>
        </div>

        <button
          onClick={onClearHistory}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyber-850 hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 border border-cyber-border text-xs font-mono transition-colors"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear Log
        </button>
      </div>

      <div className="overflow-x-auto rounded-2xl border border-cyber-border bg-cyber-900">
        <table className="w-full text-left text-xs">
          <thead className="bg-cyber-950 text-slate-400 font-mono uppercase text-[10px] border-b border-cyber-border">
            <tr>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4">Risk Rating</th>
              <th className="py-3 px-4">URL</th>
              <th className="py-3 px-4">Host / Domain</th>
              <th className="py-3 px-4">Threats</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/60">
            {history.map((item, idx) => (
              <tr key={idx} className="hover:bg-cyber-850/50 transition-colors">
                <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono">
                  {new Date(item.scannedAt).toLocaleTimeString()}
                </td>

                <td className="py-3 px-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${
                      item.riskScore >= 70 ? 'bg-rose-500' : item.riskScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`} />
                    <span className="font-mono font-bold text-white">{item.riskScore}/100</span>
                    <span className="text-[10px] text-slate-400">({item.riskLevel})</span>
                  </div>
                </td>

                <td className="py-3 px-4 font-mono max-w-xs truncate text-slate-300" title={item.url}>
                  {item.url}
                </td>

                <td className="py-3 px-4 font-mono text-slate-400">
                  {item.rootDomain || item.hostname}
                </td>

                <td className="py-3 px-4 font-mono">
                  {item.threatsFound?.length > 0 ? (
                    <span className="text-rose-400 font-semibold">{item.threatsFound.length} Detected</span>
                  ) : (
                    <span className="text-emerald-400">0 Flags</span>
                  )}
                </td>

                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <button
                    onClick={() => onSelectResult(item)}
                    className="flex items-center gap-1 ml-auto text-cyan-400 hover:text-cyan-300 font-mono text-xs hover:underline"
                  >
                    <span>View Report</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
