import React, { useState, useEffect } from 'react';
import { 
  Radar, Search, Sparkles, RefreshCw, X, AlertCircle 
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { ScanResults } from './components/ScanResults';
import { BatchScanner } from './components/BatchScanner';
import { DefangerTool } from './components/DefangerTool';
import { ThreatHistory } from './components/ThreatHistory';
import { SecurityAcademy } from './components/SecurityAcademy';
import { LiveIntelligence } from './components/LiveIntelligence';
import { ScanResult, DemoPreset } from './types';
import { apiUrl } from './api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'single' | 'batch' | 'defang' | 'history' | 'academy' | 'intel'>('single');
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [demoPresets, setDemoPresets] = useState<DemoPreset[]>([]);
  const [serverOnline, setServerOnline] = useState(true);

  // Load history from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('aegisguard_history');
      if (saved) {
        setHistory(JSON.parse(saved));
      }
    } catch (e) {
      console.warn('Could not load history from localStorage', e);
    }
  }, []);

  // Save history to localStorage
  const saveToHistory = (item: ScanResult) => {
    setHistory(prev => {
      // Remove duplicate of same URL if exists, put newest at top
      const filtered = prev.filter(h => h.url !== item.url);
      const updated = [item, ...filtered].slice(0, 50);
      try {
        localStorage.setItem('aegisguard_history', JSON.stringify(updated));
      } catch (e) {
        console.warn('Could not save to localStorage', e);
      }
      return updated;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('aegisguard_history');
    } catch (e) {
      console.warn(e);
    }
  };

  // Check backend health & fetch sample demo URLs
  useEffect(() => {
    fetch(apiUrl('/api/health'))
      .then(res => res.json())
      .then(() => setServerOnline(true))
      .catch(() => setServerOnline(false));

    fetch(apiUrl('/api/sample-urls'))
      .then(res => res.json())
      .then(data => setDemoPresets(data))
      .catch(() => {
        // Fallback default presets if server offline
        setDemoPresets([
          {
            category: 'Safe & Verified',
            label: 'GitHub Official',
            url: 'https://github.com/security',
            expectedScore: '0-10'
          },
          {
            category: 'Brand Phishing',
            label: 'PayPal Spoof',
            url: 'http://paypa1-security-verification.xyz/login',
            expectedScore: '80-100'
          },
          {
            category: 'Homograph Attack',
            label: 'Cyrillic Apple',
            url: 'http://аррӏе.com/login',
            expectedScore: '75-100'
          },
          {
            category: 'Malware Host',
            label: 'Raw IP Host',
            url: 'http://192.168.1.105:8080/admin',
            expectedScore: '60-85'
          }
        ]);
      });
  }, []);

  const handleScan = async (targetUrl?: string) => {
    const urlToScan = (targetUrl || urlInput).trim();
    if (!urlToScan) {
      setError('Please provide a URL to analyze.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch(apiUrl('/api/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to scan URL');
      }

      const data: ScanResult = await res.json();
      setCurrentResult(data);
      saveToHistory(data);
      if (targetUrl) {
        setUrlInput(targetUrl);
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during URL inspection.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectHistoryOrBatchItem = (item: ScanResult) => {
    setCurrentResult(item);
    setUrlInput(item.url);
    setActiveTab('single');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-cyber-950 text-slate-100 cyber-grid flex flex-col">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} serverOnline={serverOnline} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* TAB 1: SINGLE URL SCANNER */}
        {activeTab === 'single' && (
          <div className="space-y-8">
            {/* Hero / Header */}
            <div className="text-center max-w-3xl mx-auto space-y-3">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800/80 text-cyan-400 text-xs font-mono">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Next-Gen Multi-Layer URL Risk Assessment</span>
              </div>
              <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight font-mono text-white">
                Detect Malicious & Phishing Links in Real-Time
              </h1>
              <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
                Autonomous heuristic engine inspecting character entropy, homoglyph deception, typosquatting, brand impersonation, and live DNS/SSL cryptographic telemetry.
              </p>
            </div>

            {/* URL Input Bar */}
            <div className="max-w-3xl mx-auto">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleScan();
                }}
                className="relative flex items-center"
              >
                <div className="relative w-full">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
                    <Search className="w-5 h-5" />
                  </div>
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="Enter or paste any link (e.g. paypal-verify.xyz, http://192.168.1.1, https://google.com)"
                    className="w-full pl-11 pr-24 py-4 rounded-2xl bg-cyber-900 border border-cyber-border font-mono text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 shadow-xl transition-all"
                  />
                  {urlInput && (
                    <button
                      type="button"
                      onClick={() => setUrlInput('')}
                      className="absolute inset-y-0 right-28 flex items-center pr-2 text-slate-500 hover:text-slate-300"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="absolute right-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-mono text-xs uppercase tracking-wider font-semibold shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2 disabled:opacity-50"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Scanning...</span>
                    </>
                  ) : (
                    <>
                      <Radar className="w-4 h-4" />
                      <span>Inspect</span>
                    </>
                  )}
                </button>
              </form>

              {/* Error Alert */}
              {error && (
                <div className="mt-3 p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2 animate-shake">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {/* One-Click Demo Presets */}
              <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
                <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider mr-1">
                  Try Presets:
                </span>
                {demoPresets.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleScan(preset.url)}
                    className="px-2.5 py-1 rounded-lg bg-cyber-900 hover:bg-cyber-850 border border-cyber-border hover:border-cyan-500/40 text-[11px] font-mono text-slate-300 transition-colors flex items-center gap-1.5"
                  >
                    <span>{preset.label}</span>
                    <span className="text-[9px] text-slate-500">({preset.expectedScore})</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Results Display */}
            {currentResult && (
              <div className="mt-8 animate-fadeIn">
                <ScanResults result={currentResult} />
              </div>
            )}
          </div>
        )}

        {/* TAB 2: BATCH SCANNER */}
        {activeTab === 'batch' && (
          <BatchScanner onSelectResult={handleSelectHistoryOrBatchItem} />
        )}

        {/* TAB 3: LIVE GLOBAL INTELLIGENCE (DATABASE) */}
        {activeTab === 'intel' && (
          <LiveIntelligence onSelectResult={handleSelectHistoryOrBatchItem} />
        )}

        {/* TAB 4: DEFANGER TOOL */}
        {activeTab === 'defang' && (
          <DefangerTool />
        )}

        {/* TAB 5: AUDIT HISTORY */}
        {activeTab === 'history' && (
          <ThreatHistory
            history={history}
            onSelectResult={handleSelectHistoryOrBatchItem}
            onClearHistory={handleClearHistory}
          />
        )}

        {/* TAB 6: SECURITY ACADEMY */}
        {activeTab === 'academy' && (
          <SecurityAcademy />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-cyber-border bg-cyber-900/60 py-6 mt-12 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span className="text-slate-400 font-bold">AegisGuard Threat Intelligence Suite</span>
          </div>
          <p>
            Real-time heuristic evaluation &bull; Live DNS &bull; SSL/TLS Cryptographic Probe &bull; IDN Homoglyph Defense
          </p>
        </div>
      </footer>
    </div>
  );
};
