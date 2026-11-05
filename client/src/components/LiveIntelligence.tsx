import React, { useState, useEffect } from 'react';
import { 
  Database, RefreshCw, Globe, ShieldAlert, ShieldCheck, 
  Activity, ArrowUpRight, Flame, BarChart3, Wifi
} from 'lucide-react';
import { ScanResult } from '../types';
import { apiUrl } from '../api';

interface LiveIntelligenceProps {
  onSelectResult: (res: ScanResult) => void;
}

interface GlobalStats {
  total: number;
  safeCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  avgScore: number;
  topBrands: { brand: string; count: number }[];
  topTlds: { tld: string; count: number }[];
  isSupabaseConnected: boolean;
}

export const LiveIntelligence: React.FC<LiveIntelligenceProps> = ({ onSelectResult }) => {
  const [stats, setStats] = useState<GlobalStats | null>(null);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, scansRes] = await Promise.all([
        fetch(apiUrl('/api/stats')),
        fetch(apiUrl('/api/recent-scans'))
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
      if (scansRes.ok) {
        const scansData = await scansRes.json();
        setRecentScans(scansData);
      }
      setLastUpdated(new Date());
    } catch (err) {
      console.warn('Failed to fetch live intelligence data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Auto-refresh every 20 seconds
    const interval = setInterval(fetchData, 20000);
    return () => clearInterval(interval);
  }, []);

  const handleInspect = (item: any) => {
    // Convert DB row format to ScanResult
    const scanItem: ScanResult = {
      url: item.url,
      normalizedUrl: item.url,
      defangedUrl: item.url.replace(/^https?:\/\//i, 'hxxp[://]').replace(/\./g, '[.]'),
      riskScore: item.risk_score ?? item.riskScore ?? 0,
      riskLevel: item.risk_level ?? item.riskLevel ?? 'Safe',
      riskColor: item.risk_color ?? item.riskColor ?? 'emerald',
      hostname: item.hostname || item.url,
      rootDomain: item.root_domain || item.rootDomain || '',
      subdomain: null,
      tld: item.tld || '',
      protocol: item.protocol || 'http',
      pathname: '',
      entropy: { host: 2.5, path: 1.0 },
      checklist: {
        https: { passed: item.protocol === 'https', label: 'Secure HTTPS Protocol' },
        dns: { passed: item.dns_resolved ?? true, label: 'Active DNS Resolution' },
        sslCert: { passed: item.ssl_valid ?? false, label: 'Valid SSL/TLS Certificate' },
        homographFree: { passed: true, label: 'Clean Character Encoding' },
        structure: { passed: true, label: 'Standard URL Structure' },
        reputation: { passed: !item.targeted_brand, label: 'No Brand Impersonation' }
      },
      threatsFound: item.threats || [],
      dns: {
        resolved: item.dns_resolved ?? true,
        ipAddresses: [],
        mailServers: [],
        nameServers: []
      },
      ssl: {
        hasSSL: item.ssl_valid ?? false,
        valid: item.ssl_valid ?? false
      },
      targetedBrand: item.targeted_brand || item.targetedBrand || null,
      recommendations: item.risk_score >= 70 ? ['Avoid this domain. Credential theft threat.'] : ['Standard domain.'],
      scannedAt: item.created_at || new Date().toISOString()
    };
    onSelectResult(scanItem);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="flex h-2.5 w-2.5 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
            <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-semibold">
              Live Global Telemetry
            </span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-[11px] font-mono text-slate-400">
              Database: {stats?.isSupabaseConnected ? (
                <span className="text-emerald-400 font-bold">Supabase PostgreSQL (Live)</span>
              ) : (
                <span className="text-amber-400 font-bold">Local Sync Engine</span>
              )}
            </span>
          </div>

          <h2 className="text-lg sm:text-2xl font-bold font-mono text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            Global Threat Intelligence Database
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time feed of all URL scans submitted by users worldwide on Render.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-cyber-850 hover:bg-cyber-800 text-cyan-400 border border-cyber-border text-xs font-mono transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Feed
          </button>
        </div>
      </div>

      {/* Global Metrics Cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-border">
            <span className="text-[11px] uppercase font-mono text-slate-400 block">Total Scans (All Users)</span>
            <span className="text-2xl font-bold font-mono text-white mt-1 block">{stats.total}</span>
            <span className="text-[10px] text-cyan-400 font-mono mt-0.5 block flex items-center gap-1">
              <Wifi className="w-3 h-3" /> Live Synced
            </span>
          </div>

          <div className="p-4 rounded-xl bg-cyber-900 border border-rose-500/30">
            <span className="text-[11px] uppercase font-mono text-rose-400 block">Malicious Threats</span>
            <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">{stats.maliciousCount}</span>
            <span className="text-[10px] text-slate-500 font-mono mt-0.5 block">
              {stats.total > 0 ? Math.round((stats.maliciousCount / stats.total) * 100) : 0}% of global traffic
            </span>
          </div>

          <div className="p-4 rounded-xl bg-cyber-900 border border-amber-500/30">
            <span className="text-[11px] uppercase font-mono text-amber-400 block">Suspicious URLs</span>
            <span className="text-2xl font-bold font-mono text-amber-400 mt-1 block">{stats.suspiciousCount}</span>
            <span className="text-[10px] text-slate-500 font-mono mt-0.5 block">
              {stats.total > 0 ? Math.round((stats.suspiciousCount / stats.total) * 100) : 0}% under review
            </span>
          </div>

          <div className="p-4 rounded-xl bg-cyber-900 border border-emerald-500/30">
            <span className="text-[11px] uppercase font-mono text-emerald-400 block">Safe URLs</span>
            <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">{stats.safeCount}</span>
            <span className="text-[10px] text-slate-500 font-mono mt-0.5 block">
              Avg Score: {stats.avgScore}/100
            </span>
          </div>
        </div>
      )}

      {/* Target Breakdown Grid (Top Brands & High-Risk TLDs) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Top Targeted Brands */}
        <div className="p-5 rounded-2xl bg-cyber-900 border border-cyber-border">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 mb-3">
            <Flame className="w-4 h-4 text-rose-400" />
            Most Targeted Brands (Spoofed)
          </h3>
          {stats?.topBrands && stats.topBrands.length > 0 ? (
            <div className="space-y-2">
              {stats.topBrands.map((b, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-cyber-950 border border-cyber-border/70 text-xs font-mono">
                  <span className="text-white font-semibold uppercase">{b.brand}</span>
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px]">
                    {b.count} Spoof{b.count > 1 ? 's' : ''}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono italic">No brand spoofing logged yet.</p>
          )}
        </div>

        {/* Top Abused TLDs */}
        <div className="p-5 rounded-2xl bg-cyber-900 border border-cyber-border">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 mb-3">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            Top Abused TLDs in Scans
          </h3>
          {stats?.topTlds && stats.topTlds.length > 0 ? (
            <div className="space-y-2">
              {stats.topTlds.map((t, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-cyber-950 border border-cyber-border/70 text-xs font-mono">
                  <span className="text-cyan-300 font-semibold">.{t.tld}</span>
                  <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px]">
                    {t.count} domain{t.count > 1 ? 's' : ''}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono italic">No TLD data logged yet.</p>
          )}
        </div>
      </div>

      {/* Global Live Feed Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Live Scan Feed ({recentScans.length} Entries from All Users)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Every scan executed on the Render backend is stored and displayed here in real time.
            </p>
          </div>
        </div>

        {recentScans.length === 0 ? (
          <div className="p-12 text-center rounded-2xl bg-cyber-900 border border-cyber-border">
            <Globe className="w-10 h-10 text-slate-600 mx-auto mb-2" />
            <h4 className="text-sm font-bold font-mono text-slate-300">No Scans Recorded Yet</h4>
            <p className="text-xs text-slate-500 mt-1">
              Scan any URL in the URL Scanner to generate your first live database entry!
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-cyber-border bg-cyber-900">
            <table className="w-full text-left text-xs">
              <thead className="bg-cyber-950 text-slate-400 font-mono uppercase text-[10px] border-b border-cyber-border">
                <tr>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-4">Risk Rating</th>
                  <th className="py-3 px-4">Scanned URL</th>
                  <th className="py-3 px-4">Domain / Brand</th>
                  <th className="py-3 px-4">Threats</th>
                  <th className="py-3 px-4">Origin IP</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/60">
                {recentScans.map((scan, idx) => {
                  const score = scan.risk_score ?? scan.riskScore ?? 0;
                  const level = scan.risk_level ?? scan.riskLevel ?? 'Safe';
                  const brand = scan.targeted_brand ?? scan.targetedBrand;
                  const threatCount = scan.threat_count ?? (scan.threats ? scan.threats.length : 0);

                  return (
                    <tr key={idx} className="hover:bg-cyber-850/50 transition-colors">
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                        {scan.created_at ? new Date(scan.created_at).toLocaleTimeString() : 'Just now'}
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${
                            score >= 70 ? 'bg-rose-500' : score >= 45 ? 'bg-amber-500' : 'bg-emerald-500'
                          }`} />
                          <span className="font-mono font-bold text-white">{score}</span>
                          <span className="text-[10px] text-slate-400">({level})</span>
                        </div>
                      </td>

                      <td className="py-3 px-4 font-mono max-w-xs truncate text-slate-200" title={scan.url}>
                        {scan.url}
                      </td>

                      <td className="py-3 px-4 font-mono text-slate-300">
                        {brand ? (
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px]">
                            {brand}
                          </span>
                        ) : (
                          scan.root_domain || scan.hostname || '-'
                        )}
                      </td>

                      <td className="py-3 px-4 font-mono">
                        {threatCount > 0 ? (
                          <span className="text-rose-400 font-semibold">{threatCount} Detected</span>
                        ) : (
                          <span className="text-emerald-400">Clean</span>
                        )}
                      </td>

                      <td className="py-3 px-4 font-mono text-slate-500 text-[11px]">
                        {scan.user_ip || 'Anonymous'}
                      </td>

                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => handleInspect(scan)}
                          className="flex items-center gap-1 ml-auto text-cyan-400 hover:text-cyan-300 font-mono text-xs hover:underline"
                        >
                          <span>Inspect</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
