import React, { useState } from 'react';
import { ShieldCheck, Copy, Check, ArrowRightLeft } from 'lucide-react';

export const DefangerTool: React.FC = () => {
  const [inputUrl, setInputUrl] = useState('https://malicious-phishing-link.top/download/ransomware.exe');
  const [outputUrl, setOutputUrl] = useState('');
  const [mode, setMode] = useState<'defang' | 'refang'>('defang');
  const [copied, setCopied] = useState(false);

  const processUrl = async (val: string, currentMode: 'defang' | 'refang') => {
    if (!val.trim()) {
      setOutputUrl('');
      return;
    }
    try {
      const res = await fetch('/api/defang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: val, action: currentMode })
      });
      const data = await res.json();
      setOutputUrl(data.result || '');
    } catch {
      // Fallback client side
      if (currentMode === 'defang') {
        setOutputUrl(
          val
            .replace(/^https:\/\//i, 'hxxps[://]')
            .replace(/^http:\/\//i, 'hxxp[://]')
            .replace(/\./g, '[.]')
        );
      } else {
        setOutputUrl(
          val
            .replace(/^hxxps(\[:\/\/\]|:\/\/)/i, 'https://')
            .replace(/^hxxp(\[:\/\/\]|:\/\/)/i, 'http://')
            .replace(/\[\.\]/g, '.')
            .replace(/\[:\/\/\]/g, '://')
        );
      }
    }
  };

  const handleToggleMode = () => {
    const nextMode = mode === 'defang' ? 'refang' : 'defang';
    setMode(nextMode);
    // Swap input and output
    if (outputUrl) {
      setInputUrl(outputUrl);
      processUrl(outputUrl, nextMode);
    }
  };

  const handleCopy = () => {
    if (!outputUrl) return;
    navigator.clipboard.writeText(outputUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Initial process on mount
  React.useEffect(() => {
    processUrl(inputUrl, mode);
  }, []);

  return (
    <div className="space-y-6">
      {/* Intro info box */}
      <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2 mb-2">
          <ShieldCheck className="w-5 h-5 text-cyan-400" />
          SOC Cyber Defanger & Link Sanitizer
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
          <strong>Defanging</strong> is a cybersecurity standard procedure for rendering malicious URLs, IP addresses, and email links harmless. It prevents automated link parsers, email security gateways, and chat apps from automatically previewing, resolving, or converting them into clickable hyperlinks during security incident reporting.
        </p>
      </div>

      {/* Converter Panel */}
      <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border space-y-6">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-300">
            Mode: <span className="text-cyan-400 font-bold">{mode === 'defang' ? 'SANITIZE / DEFANG (SAFE FOR SHARING)' : 'RESTORE / REFANG (CANONICAL URL)'}</span>
          </span>

          <button
            onClick={handleToggleMode}
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyber-850 hover:bg-cyber-800 text-cyan-400 border border-cyber-border text-xs font-mono transition-colors"
          >
            <ArrowRightLeft className="w-3.5 h-3.5" />
            Switch to {mode === 'defang' ? 'Refang' : 'Defang'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Input field */}
          <div className="space-y-2">
            <label className="text-xs font-mono uppercase text-slate-400 block">
              {mode === 'defang' ? 'Original Threat URL' : 'Defanged URL to Restore'}
            </label>
            <textarea
              rows={4}
              value={inputUrl}
              onChange={(e) => {
                setInputUrl(e.target.value);
                processUrl(e.target.value, mode);
              }}
              placeholder={mode === 'defang' ? 'https://suspicious-site.com/payload' : 'hxxps[://]suspicious-site[.]com/payload'}
              className="w-full bg-cyber-950 border border-cyber-border rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Output field */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-mono uppercase text-slate-400">
                {mode === 'defang' ? 'Defanged Result (Safe to Share)' : 'Restored Canonical URL'}
              </label>
              {outputUrl && (
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              )}
            </div>
            <div className="w-full bg-cyber-950 border border-cyber-border rounded-xl p-3 font-mono text-xs text-cyan-300 break-all min-h-[100px] flex items-center">
              {outputUrl || <span className="text-slate-600 italic">Result will appear here...</span>}
            </div>
          </div>
        </div>

        {/* Common Transformations Cheat Sheet */}
        <div className="pt-4 border-t border-cyber-border/70">
          <span className="text-[11px] font-mono text-slate-400 block mb-2 uppercase">Defanging Standard Mapping:</span>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-cyber-950 border border-cyber-border">
              <span className="text-slate-500">https://</span> → <span className="text-cyan-400">hxxps[://]</span>
            </div>
            <div className="p-2 rounded bg-cyber-950 border border-cyber-border">
              <span className="text-slate-500">http://</span> → <span className="text-cyan-400">hxxp[://]</span>
            </div>
            <div className="p-2 rounded bg-cyber-950 border border-cyber-border">
              <span className="text-slate-500">.</span> → <span className="text-cyan-400">[.]</span>
            </div>
            <div className="p-2 rounded bg-cyber-950 border border-cyber-border">
              <span className="text-slate-500">@</span> → <span className="text-cyan-400">[@]</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
