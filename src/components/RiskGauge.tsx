import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertOctagon } from 'lucide-react';
import { RiskLevel } from '../types';

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, level }) => {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  // Score is 0-100, we offset the circle stroke
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let strokeColor = '#10b981'; // emerald
  let glowClass = 'cyber-glow-emerald';
  let badgeBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  let Icon = ShieldCheck;
  let severityLabel = 'Verified Safe';

  if (score >= 75) {
    strokeColor = '#f43f5e'; // rose red
    glowClass = 'cyber-glow-rose';
    badgeBg = 'bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse';
    Icon = AlertOctagon;
    severityLabel = 'Critical Danger / Malicious';
  } else if (score >= 45) {
    strokeColor = '#f59e0b'; // amber
    glowClass = 'cyber-glow-amber';
    badgeBg = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    Icon = AlertTriangle;
    severityLabel = 'Suspicious / Elevated Risk';
  } else if (score >= 20) {
    strokeColor = '#06b6d4'; // cyan
    glowClass = 'cyber-glow-cyan';
    badgeBg = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    Icon = ShieldAlert;
    severityLabel = 'Low Risk / Caution Advised';
  }

  return (
    <div className={`relative flex flex-col items-center justify-center p-6 rounded-2xl bg-cyber-900 border border-cyber-border ${glowClass} transition-all duration-500`}>
      <div className="relative w-48 h-48 flex items-center justify-center">
        {/* SVG Circular Meter */}
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
          {/* Background track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="#161f2e"
            strokeWidth="12"
            fill="transparent"
          />
          {/* Animated score bar */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={strokeColor}
            strokeWidth="12"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <div className="text-4xl font-extrabold tracking-tight font-mono text-white">
            {score}
            <span className="text-lg text-slate-400 font-normal">/100</span>
          </div>
          <span className="text-xs font-semibold tracking-wider uppercase text-slate-400 mt-1">
            Risk Index
          </span>
        </div>
      </div>

      {/* Severity Badge */}
      <div className="mt-4 flex flex-col items-center gap-2">
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-semibold uppercase tracking-wider ${badgeBg}`}>
          <Icon className="w-4 h-4" />
          <span>{level}</span>
        </div>
        <p className="text-xs text-slate-400 text-center max-w-[220px]">
          {severityLabel}
        </p>
      </div>
    </div>
  );
};
