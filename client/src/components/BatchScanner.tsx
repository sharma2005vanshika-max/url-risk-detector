import React, { useState } from 'react';
import { Layers, Play, Download, RefreshCw } from 'lucide-react';
import { BatchResult, ScanResult } from '../types';
import { apiUrl } from '../api';

interface BatchScannerProps {
  onSelectResult: (res: ScanResult) => void;
}

const SAMPLE_BATCH = [
  'https://github.com/security',
  'https://google.com',
  'http://paypa1-security-verification.xyz/login',
  'http://аррӏе.com/verify-account',
  'http://192.168.1.105:8080/admin',
  'http://secure.account.update.bankofamerica.support-cloud.xyz'
].join('\n');

export const BatchScanner: React.FC<BatchScannerProps> = ({ onSelectResult }) => {
  const [inputText, setInputText] = useState(SAMPLE_BATCH);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<BatchResult | null>(null);
  const [filter, setFilter] = useState<'ALL' | 'Safe' | 'Suspicious' | 'Malicious'>('ALL');
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    const lines = inputText
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);

    if (lines.length === 0) {
      setError('Please enter at least one URL.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(apiUrl('/api/batch-scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls: lines })
      });

      if (!response.ok) {
        throw new Error('Batch scan failed.');
      }

      const resData = await response.json();
      setData(resData);
    } catch (err: any) {
      setError(err.message || 'Error executing batch scan');
    } finally {
      setLoading(false);
    }
  };

  const exportCSV = () => {
    if (!data) return;
    const headers = ['URL', 'Risk Score', 'Risk Level', 'Protocol', 'Root Domain', 'Threats Count'];
    const rows = data.results.map(r => [
      `"${r.url}"`,
      r.riskScore,
      `"${r.riskLevel}"`,
      `"${r.protocol}"`,
      `"${r.rootDomain}"`,
      r.threatsFound?.length || 0
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `aegisguard-batch-scan-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredResults = data?.results.filter(r => {
    if (filter === 'ALL') return true;
    if (filter === 'Safe') return r.riskLevel === 'Safe' || r.riskLevel === 'Low Risk';
    return r.riskLevel === filter;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Input Box */}
      <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Batch URL Threat Scanner
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Paste up to 30 URLs (one per line) for concurrent heuristic, DNS, and reputation analysis.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setInputText(SAMPLE_BATCH)}
              className="text-xs px-2.5 py-1 rounded-lg bg-cyber-850 hover:bg-cyber-800 text-slate-300 border border-cyber-border transition-colors"
            >
              Load Demo Threats
            </button>
            <button
              onClick={() => setInputText('')}
              className="text-xs px-2.5 py-1 rounded-lg bg-cyber-850 hover:bg-cyber-800 text-slate-400 border border-cyber-border transition-colors"
            >
              Clear
            </button>
          </div>
        </div>

        <textarea
          rows={6}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="https://example.com&#10;http://phishing-site.xyz/login&#10;http://192.168.1.1"
          className="w-full bg-cyber-950 border border-cyber-border rounded-xl p-3.5 font-mono text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
        />

        {error && (
          <p className="text-xs text-rose-400 mt-2">{error}</p>
        )}

        <div className="mt-4 flex items-center justify-between">
          <span className="text-xs text-slate-500 font-mono">
            {inputText.split('\n').filter(l => l.trim()).length} URLs queued
          </span>

          <button
            onClick={handleScan}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-medium text-xs font-mono tracking-wider uppercase transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Scanning Batch...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white" />
                Analyze Batch
              </>
            )}
          </button>
        </div>
      </div>

      {/* Batch Results & Summary */}
      {data && (
        <div className="space-y-6">
          {/* Metrics summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-border">
              <span className="text-[11px] uppercase font-mono text-slate-400 block">Total Scanned</span>
              <span className="text-2xl font-bold font-mono text-white mt-1 block">{data.summary.total}</span>
            </div>

            <div className="p-4 rounded-xl bg-cyber-900 border border-emerald-500/20">
              <span className="text-[11px] uppercase font-mono text-emerald-400 block">Safe URLs</span>
              <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">{data.summary.safeCount}</span>
            </div>

            <div className="p-4 rounded-xl bg-cyber-900 border border-amber-500/20">
              <span className="text-[11px] uppercase font-mono text-amber-400 block">Suspicious URLs</span>
              <span className="text-2xl font-bold font-mono text-amber-400 mt-1 block">{data.summary.suspiciousCount}</span>
            </div>

            <div className="p-4 rounded-xl bg-cyber-900 border border-rose-500/20">
              <span className="text-[11px] uppercase font-mono text-rose-400 block">Malicious Threats</span>
              <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">{data.summary.maliciousCount}</span>
            </div>
          </div>

          {/* Table Controls */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-1 bg-cyber-950 p-1 rounded-xl border border-cyber-border">
              {(['ALL', 'Safe', 'Suspicious', 'Malicious'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition-colors ${
                    filter === f ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>

            <button
              onClick={exportCSV}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-cyber-850 hover:bg-cyber-800 text-slate-300 border border-cyber-border text-xs font-mono transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export CSV
            </button>
          </div>

          {/* Results Table */}
          <div className="overflow-x-auto rounded-2xl border border-cyber-border bg-cyber-900">
            <table className="w-full text-left text-xs">
              <thead className="bg-cyber-950 text-slate-400 font-mono uppercase text-[10px] border-b border-cyber-border">
                <tr>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">URL</th>
                  <th className="py-3 px-4">Domain</th>
                  <th className="py-3 px-4">Threats</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/60">
                {filteredResults.map((item, idx) => (
                  <tr key={idx} className="hover:bg-cyber-850/50 transition-colors">
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          item.riskLevel === 'Malicious' ? 'bg-rose-500' : item.riskLevel === 'Suspicious' ? 'bg-amber-500' : 'bg-emerald-500'
                        }`} />
                        <span className="font-mono font-bold text-white">{item.riskScore}</span>
                        <span className="text-[10px] text-slate-400">({item.riskLevel})</span>
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono max-w-xs truncate text-slate-300" title={item.url}>
                      {item.url}
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400">
                      {item.rootDomain || '-'}
                    </td>

                    <td className="py-3 px-4">
                      {item.threatsFound?.length > 0 ? (
                        <span className="text-rose-400 font-mono font-semibold">
                          {item.threatsFound.length} Threat{item.threatsFound.length > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="text-emerald-400 font-mono">Clean</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectResult(item)}
                        className="text-cyan-400 hover:text-cyan-300 font-mono text-xs hover:underline"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
