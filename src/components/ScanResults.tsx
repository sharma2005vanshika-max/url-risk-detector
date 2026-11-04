import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, CheckCircle2, XCircle, 
  Copy, Check, Globe, Lock, Activity, ArrowRight 
} from 'lucide-react';
import { ScanResult } from '../types';
import { RiskGauge } from './RiskGauge';

interface ScanResultsProps {
  result: ScanResult;
}

export const ScanResults: React.FC<ScanResultsProps> = ({ result }) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/50';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/50';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/50';
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/50';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Score Gauge + Overview Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <RiskGauge score={result.riskScore} level={result.riskLevel} />

        <div className="lg:col-span-2 p-6 rounded-2xl bg-cyber-900 border border-cyber-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3 mb-4">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Inspection Target
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {new Date(result.scannedAt).toLocaleTimeString()}
              </span>
            </div>

            <div className="break-all font-mono text-sm sm:text-base font-semibold text-white bg-cyber-950 p-3.5 rounded-xl border border-cyber-border/80 flex items-center justify-between gap-3">
              <span className="truncate">{result.url}</span>
              <button
                onClick={() => copyToClipboard(result.url)}
                className="p-1.5 rounded-lg bg-cyber-850 hover:bg-cyber-700 text-slate-300 transition-colors shrink-0"
                title="Copy URL"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>

            {/* Defanged preview for safe sharing */}
            <div className="mt-3 flex items-center gap-2 text-xs text-slate-400">
              <span className="font-semibold text-slate-300">Defanged:</span>
              <code className="font-mono bg-cyber-950 px-2 py-0.5 rounded border border-cyber-border text-cyan-400 truncate">
                {result.defangedUrl}
              </code>
              <button
                onClick={() => copyToClipboard(result.defangedUrl)}
                className="text-cyan-400 hover:text-cyan-300 ml-auto flex items-center gap-1 text-[11px]"
              >
                Copy Defanged
              </button>
            </div>
          </div>

          {/* Quick Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-4 border-t border-cyber-border/70">
            <div className="bg-cyber-950/60 p-2.5 rounded-xl border border-cyber-border/50">
              <span className="text-[10px] uppercase font-mono text-slate-500 block">Root Domain</span>
              <span className="text-xs font-semibold text-slate-200 truncate block font-mono">{result.rootDomain}</span>
            </div>

            <div className="bg-cyber-950/60 p-2.5 rounded-xl border border-cyber-border/50">
              <span className="text-[10px] uppercase font-mono text-slate-500 block">Protocol</span>
              <span className="text-xs font-semibold text-slate-200 uppercase block font-mono">{result.protocol}</span>
            </div>

            <div className="bg-cyber-950/60 p-2.5 rounded-xl border border-cyber-border/50">
              <span className="text-[10px] uppercase font-mono text-slate-500 block">Host Entropy</span>
              <span className="text-xs font-semibold text-slate-200 block font-mono">{result.entropy.host} <span className="text-[10px] text-slate-500">/ 5.0</span></span>
            </div>

            <div className="bg-cyber-950/60 p-2.5 rounded-xl border border-cyber-border/50">
              <span className="text-[10px] uppercase font-mono text-slate-500 block">Threat Count</span>
              <span className={`text-xs font-semibold font-mono block ${result.threatsFound.length > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {result.threatsFound.length} Detected
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Checklist (6-Point Inspection) */}
      <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-cyan-400" />
          Multi-Vector Security Checklist
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {Object.entries(result.checklist).map(([key, item]) => (
            <div
              key={key}
              className={`flex items-center gap-3 p-3 rounded-xl border transition-all ${
                item.passed
                  ? 'bg-emerald-950/20 border-emerald-900/40 text-emerald-300'
                  : 'bg-rose-950/20 border-rose-900/40 text-rose-300'
              }`}
            >
              {item.passed ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              ) : (
                <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
              )}
              <span className="text-xs font-medium">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Detected Threats Section */}
      {result.threatsFound.length > 0 ? (
        <div className="p-6 rounded-2xl bg-cyber-900 border border-rose-500/30 cyber-glow-rose">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-rose-400 font-mono flex items-center gap-2">
              <ShieldAlert className="w-5 h-5" />
              Detected Threat Vectors ({result.threatsFound.length})
            </h3>
            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
              Immediate Action Required
            </span>
          </div>

          <div className="space-y-3">
            {result.threatsFound.map((threat, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-cyber-950/80 border border-cyber-border/80 hover:border-cyber-border transition-all"
              >
                <div className="flex flex-wrap items-center gap-2 mb-1.5">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase font-mono ${getSeverityBadge(threat.severity)}`}>
                    {threat.severity}
                  </span>
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                    {threat.category}
                  </span>
                  <h4 className="text-xs sm:text-sm font-bold text-slate-100 ml-1">
                    {threat.title}
                  </h4>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pl-1">
                  {threat.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="p-6 rounded-2xl bg-cyber-900 border border-emerald-500/30 cyber-glow-emerald flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-emerald-300">Clean Threat Profile</h4>
            <p className="text-xs text-slate-400 mt-0.5">
              No known typosquatting, homoglyph deception, phishing keywords, or malicious routing patterns were detected on this target.
            </p>
          </div>
        </div>
      )}

      {/* Network & Cryptographic Telemetry (DNS & SSL) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* DNS Telemetry */}
        <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 mb-4">
            <Globe className="w-4 h-4 text-cyan-400" />
            DNS & Infrastructure Records
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-cyber-border/50">
              <span className="text-slate-400">DNS Status</span>
              <span className={`font-mono font-semibold ${result.dns.resolved ? 'text-emerald-400' : 'text-rose-400'}`}>
                {result.dns.resolved ? 'RESOLVED (ACTIVE)' : 'NXDOMAIN / INACTIVE'}
              </span>
            </div>

            <div className="py-2 border-b border-cyber-border/50">
              <span className="text-slate-400 block mb-1">A / AAAA IP Addresses:</span>
              <div className="flex flex-wrap gap-1.5">
                {result.dns.ipAddresses.length > 0 ? (
                  result.dns.ipAddresses.map((ip, i) => (
                    <span key={i} className="font-mono bg-cyber-950 px-2 py-0.5 rounded border border-cyber-border text-cyan-300">
                      {ip}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 italic">No A records found</span>
                )}
              </div>
            </div>

            <div className="py-2 border-b border-cyber-border/50">
              <span className="text-slate-400 block mb-1">Mail Servers (MX):</span>
              <div className="flex flex-wrap gap-1.5">
                {result.dns.mailServers.length > 0 ? (
                  result.dns.mailServers.map((mx, i) => (
                    <span key={i} className="font-mono bg-cyber-950 px-2 py-0.5 rounded border border-cyber-border text-slate-300 truncate max-w-full">
                      {mx}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 italic">No MX records configured</span>
                )}
              </div>
            </div>

            <div className="py-2">
              <span className="text-slate-400 block mb-1">Authoritative Nameservers:</span>
              <div className="flex flex-wrap gap-1.5">
                {result.dns.nameServers.length > 0 ? (
                  result.dns.nameServers.map((ns, i) => (
                    <span key={i} className="font-mono bg-cyber-950 px-2 py-0.5 rounded border border-cyber-border text-slate-400 truncate max-w-full">
                      {ns}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 italic">Nameservers unlisted</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* SSL/TLS Handshake Telemetry */}
        <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 mb-4">
            <Lock className="w-4 h-4 text-cyan-400" />
            SSL / TLS Certificate Probe
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-cyber-border/50">
              <span className="text-slate-400">Handshake Status</span>
              <span className={`font-mono font-semibold ${result.ssl.valid ? 'text-emerald-400' : 'text-amber-400'}`}>
                {result.ssl.valid ? 'AUTHORIZED & VALID' : result.ssl.hasSSL ? 'INVALID / SELF-SIGNED' : 'NO SSL HANDSHAKE'}
              </span>
            </div>

            <div className="flex justify-between items-center py-2 border-b border-cyber-border/50">
              <span className="text-slate-400">Certificate Authority (Issuer)</span>
              <span className="font-mono text-slate-200 truncate max-w-[200px]" title={result.ssl.issuer || 'N/A'}>
                {result.ssl.issuer || 'N/A'}
              </span>
            </div>

            <div className="flex justify-between items-center py-2 border-b border-cyber-border/50">
              <span className="text-slate-400">Expiration Date</span>
              <span className="font-mono text-slate-200">
                {result.ssl.validTo || 'N/A'}
              </span>
            </div>

            <div className="flex justify-between items-center py-2">
              <span className="text-slate-400">Days Remaining</span>
              <span className={`font-mono font-semibold ${
                result.ssl.daysRemaining !== null && result.ssl.daysRemaining !== undefined && result.ssl.daysRemaining < 15
                  ? 'text-rose-400'
                  : 'text-emerald-400'
              }`}>
                {result.ssl.daysRemaining !== null && result.ssl.daysRemaining !== undefined
                  ? `${result.ssl.daysRemaining} days`
                  : 'N/A'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Actionable Recommendations */}
      <div className="p-6 rounded-2xl bg-cyber-950 border border-cyber-border">
        <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono mb-3">
          SOC Safety Recommendations
        </h4>
        <ul className="space-y-2">
          {result.recommendations.map((rec, i) => (
            <li key={i} className="flex items-start gap-2.5 text-xs text-slate-300">
              <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
