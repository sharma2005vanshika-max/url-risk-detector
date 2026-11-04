import React from 'react';
import { Shield, Radar, Layers, ShieldCheck, History, BookOpen } from 'lucide-react';

interface NavbarProps {
  activeTab: 'single' | 'batch' | 'defang' | 'history' | 'academy';
  setActiveTab: (tab: 'single' | 'batch' | 'defang' | 'history' | 'academy') => void;
  serverOnline: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, serverOnline }) => {
  return (
    <header className="border-b border-cyber-border bg-cyber-900/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-black tracking-wider text-white font-mono">
                  AEGIS<span className="text-cyan-400">GUARD</span>
                </span>
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  v1.0 SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400">URL Threat & Phishing Intelligence</p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1 bg-cyber-950 p-1 rounded-xl border border-cyber-border">
            <button
              onClick={() => setActiveTab('single')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'single'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-850'
              }`}
            >
              <Radar className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('batch')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'batch'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-850'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Batch Scan</span>
            </button>

            <button
              onClick={() => setActiveTab('defang')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'defang'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-850'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Defanger</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'history'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-850'
              }`}
            >
              <History className="w-4 h-4" />
              <span>Audit Log</span>
            </button>

            <button
              onClick={() => setActiveTab('academy')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'academy'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-850'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Security Academy</span>
            </button>
          </nav>

          {/* Engine Status */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyber-950 border border-cyber-border text-xs">
              <span className={`w-2 h-2 rounded-full ${serverOnline ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              <span className="text-[11px] text-slate-300 font-mono">
                {serverOnline ? 'ENGINE READY' : 'OFFLINE'}
              </span>
            </div>
          </div>
        </div>

        {/* Mobile Navigation Row */}
        <div className="flex md:hidden items-center justify-around py-2 border-t border-cyber-border/50 text-xs">
          <button
            onClick={() => setActiveTab('single')}
            className={`flex flex-col items-center gap-1 ${activeTab === 'single' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <Radar className="w-4 h-4" />
            <span className="text-[10px]">Scanner</span>
          </button>
          <button
            onClick={() => setActiveTab('batch')}
            className={`flex flex-col items-center gap-1 ${activeTab === 'batch' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <Layers className="w-4 h-4" />
            <span className="text-[10px]">Batch</span>
          </button>
          <button
            onClick={() => setActiveTab('defang')}
            className={`flex flex-col items-center gap-1 ${activeTab === 'defang' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span className="text-[10px]">Defang</span>
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`flex flex-col items-center gap-1 ${activeTab === 'history' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <History className="w-4 h-4" />
            <span className="text-[10px]">History</span>
          </button>
          <button
            onClick={() => setActiveTab('academy')}
            className={`flex flex-col items-center gap-1 ${activeTab === 'academy' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <BookOpen className="w-4 h-4" />
            <span className="text-[10px]">Academy</span>
          </button>
        </div>
      </div>
    </header>
  );
};
