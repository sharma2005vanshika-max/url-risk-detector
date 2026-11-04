import React from 'react';
import { BookOpen, ShieldAlert, Cpu, Eye, FileText, CheckCircle2 } from 'lucide-react';

export const SecurityAcademy: React.FC = () => {
  const topics = [
    {
      title: 'IDN Homograph Attacks',
      badge: 'Visual Spoofing',
      icon: Eye,
      description:
        'Internationalized Domain Names (IDNs) allow non-ASCII scripts like Cyrillic, Greek, and Hebrew. Attackers register domains with characters that look identical to Latin characters (e.g., Cyrillic "а" U+0430 looks identical to Latin "a" U+0061). To the naked eye, "аррӏе.com" appears legitimate, but it resolves to an attacker-controlled server.',
      example: 'Latin apple.com vs Cyrillic аррӏе.com (Punycode: xn--e1afmkfd.com)'
    },
    {
      title: 'Typosquatting & Combosquatting',
      badge: 'Brand Impersonation',
      icon: ShieldAlert,
      description:
        'Typosquatting exploits typing slips and phonetic mimics (e.g., substituting "1" for "l", "0" for "o", "rn" for "m"). Combosquatting prepends or appends trust terms to real brand names (e.g., "paypal-security-update.com" or "bankofamerica-auth.net") to deceive victims into submitting login credentials.',
      example: 'Legitimate: paypal.com | Typosquat: paypa1.com, paypaI.com, paypal-verify.xyz'
    },
    {
      title: 'Shannon Entropy & DGAs',
      badge: 'Algorithmic Detection',
      icon: Cpu,
      description:
        'Shannon entropy quantifies the unpredictability or randomness of characters in a string. Legitimate human-readable domains typically have an entropy score between 2.0 and 3.5. Domain Generation Algorithms (DGAs) used by ransomware and malware botnets produce random strings with high entropy (> 3.9).',
      example: 'Standard: google.com (entropy ~2.1) vs DGA: xk79a-q99z01k4.xyz (entropy > 4.2)'
    },
    {
      title: 'Subdomain Camouflage Tricks',
      badge: 'DNS Deception',
      icon: FileText,
      description:
        'Because users read left-to-right, attackers create elaborate subdomains on disposable hosting. For instance, in "chase.com.security-alert.org", "chase.com" is merely a third-level subdomain, while the actual controlling root domain is "security-alert.org".',
      example: 'http://paypal.com.account-update.temporary-host.top'
    }
  ];

  return (
    <div className="space-y-6">
      <div className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2 mb-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          Threat Intelligence Academy & Attack Taxonomy
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
          Learn how cyber adversaries construct malicious links, manipulate human cognition, and deceive standard browser defenses. AegisGuard actively parses and scores against each of these attack vectors in real-time.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {topics.map((t, idx) => {
          const Icon = t.icon;
          return (
            <div
              key={idx}
              className="p-6 rounded-2xl bg-cyber-900 border border-cyber-border hover:border-cyan-500/40 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                    {t.badge}
                  </span>
                  <Icon className="w-5 h-5 text-cyan-400" />
                </div>
                <h4 className="text-sm font-bold text-white mb-2 font-mono">{t.title}</h4>
                <p className="text-xs text-slate-300 leading-relaxed mb-4">{t.description}</p>
              </div>

              <div className="bg-cyber-950 p-3 rounded-xl border border-cyber-border/80">
                <span className="text-[10px] uppercase font-mono text-slate-500 block mb-1">Illustration / Anatomy</span>
                <code className="text-xs font-mono text-cyan-400 break-all">{t.example}</code>
              </div>
            </div>
          );
        })}
      </div>

      {/* Prevention Checklist */}
      <div className="p-6 rounded-2xl bg-cyber-950 border border-cyber-border">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono mb-4 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          Best Practices for Phishing Defense
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs text-slate-300">
          <div className="p-3 rounded-xl bg-cyber-900 border border-cyber-border/50">
            <span className="font-bold text-white block mb-1">1. Check the Root Domain</span>
            <p className="text-slate-400 text-[11px]">
              Always identify the primary domain right before the top-level extension (.com, .org), ignoring preceding subdomains.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-cyber-900 border border-cyber-border/50">
            <span className="font-bold text-white block mb-1">2. Inspect Certificates</span>
            <p className="text-slate-400 text-[11px]">
              HTTPS encrypts traffic, but does NOT guarantee legitimacy. Over 80% of phishing sites use free SSL certificates.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-cyber-900 border border-cyber-border/50">
            <span className="font-bold text-white block mb-1">3. Defang Before Sharing</span>
            <p className="text-slate-400 text-[11px]">
              When forwarding suspicious links to IT or security analysts, always defang the URL to prevent accidental clicks.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
