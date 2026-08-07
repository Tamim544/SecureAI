"use client";

import { motion } from "framer-motion";
import { ShieldAlert, CheckCircle, Clock, Activity, ArrowRight, ShieldCheck } from "lucide-react";

export default function Home() {
  const stats = [
    { label: "Scans Today", value: "24", icon: <Activity className="w-5 h-5 text-primary" />, change: "+12%" },
    { label: "Critical Findings", value: "3", icon: <ShieldAlert className="w-5 h-5 text-destructive" />, change: "-2%" },
    { label: "Projects Secured", value: "12", icon: <ShieldCheck className="w-5 h-5 text-success" />, change: "+1" },
    { label: "Avg. Scan Time", value: "4.2s", icon: <Clock className="w-5 h-5 text-warning" />, change: "-0.5s" },
  ];

  const recentFindings = [
    { id: "VULN-092", cwe: "CWE-89", severity: "CRITICAL", file: "auth.py", project: "backend-api", time: "10 min ago" },
    { id: "VULN-091", cwe: "CWE-79", severity: "HIGH", file: "components/Header.tsx", project: "web-client", time: "25 min ago" },
    { id: "VULN-090", cwe: "CWE-502", severity: "CRITICAL", file: "utils/session.py", project: "backend-api", time: "1 hour ago" },
    { id: "VULN-089", cwe: "CWE-22", severity: "MEDIUM", file: "api/download.js", project: "legacy-service", time: "3 hours ago" },
  ];

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case "CRITICAL": return "bg-destructive/20 text-destructive border-destructive/30";
      case "HIGH": return "bg-orange-500/20 text-orange-500 border-orange-500/30";
      case "MEDIUM": return "bg-warning/20 text-warning border-warning/30";
      default: return "bg-blue-500/20 text-blue-500 border-blue-500/30";
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: { y: 0, opacity: 1 }
  };

  return (
    <motion.div 
      className="max-w-7xl mx-auto space-y-8 relative z-10"
      initial="hidden"
      animate="visible"
      variants={containerVariants}
    >
      <div className="flex justify-between items-end">
        <div>
          <motion.h2 variants={itemVariants} className="text-3xl font-bold tracking-tight text-white mb-2">
            Overview
          </motion.h2>
          <motion.p variants={itemVariants} className="text-muted-foreground">
            Real-time security posture and recent vulnerability findings.
          </motion.p>
        </div>
      </div>

      {/* Stats Grid */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, i) => (
          <div key={i} className="glass-card p-6 flex flex-col gap-4 relative overflow-hidden group hover:border-white/10 transition-colors cursor-default">
            <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-white/5 to-transparent rounded-full blur-2xl -mr-10 -mt-10 group-hover:bg-white/10 transition-colors"></div>
            <div className="flex justify-between items-start">
              <div className="p-3 bg-secondary/50 rounded-xl border border-white/5">
                {stat.icon}
              </div>
              <span className={`text-xs font-medium px-2 py-1 rounded-full ${stat.change.startsWith('+') ? 'bg-success/20 text-success' : stat.change.startsWith('-') && stat.label.includes('Time') ? 'bg-success/20 text-success' : 'bg-destructive/20 text-destructive'}`}>
                {stat.change}
              </span>
            </div>
            <div>
              <h3 className="text-3xl font-bold text-white mb-1">{stat.value}</h3>
              <p className="text-sm text-muted-foreground font-medium">{stat.label}</p>
            </div>
          </div>
        ))}
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Findings Table */}
        <motion.div variants={itemVariants} className="lg:col-span-2 glass-card overflow-hidden flex flex-col">
          <div className="p-6 border-b border-white/5 flex justify-between items-center bg-secondary/20">
            <h3 className="text-lg font-semibold text-white">Recent Findings</h3>
            <button className="text-sm text-primary hover:text-primary/80 font-medium flex items-center gap-1 transition-colors">
              View All <ArrowRight className="w-4 h-4" />
            </button>
          </div>
          <div className="flex-1 overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-muted-foreground uppercase bg-secondary/10 border-b border-white/5">
                <tr>
                  <th className="px-6 py-4 font-medium">Finding ID</th>
                  <th className="px-6 py-4 font-medium">Severity</th>
                  <th className="px-6 py-4 font-medium">CWE</th>
                  <th className="px-6 py-4 font-medium">Location</th>
                  <th className="px-6 py-4 font-medium text-right">Detected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {recentFindings.map((finding) => (
                  <tr key={finding.id} className="hover:bg-white/[0.02] transition-colors group cursor-pointer">
                    <td className="px-6 py-4 font-medium text-white group-hover:text-primary transition-colors">
                      {finding.id}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${getSeverityStyle(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-white font-medium">{finding.cwe}</td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <span className="text-white">{finding.file}</span>
                        <span className="text-xs text-muted-foreground">{finding.project}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right text-muted-foreground">{finding.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Action Panel */}
        <motion.div variants={itemVariants} className="glass-card p-6 flex flex-col gap-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl pointer-events-none"></div>
          
          <div>
            <h3 className="text-lg font-semibold text-white mb-2">Automated Fixes</h3>
            <p className="text-sm text-muted-foreground">
              Your AI model has generated fixes for 2 critical vulnerabilities.
            </p>
          </div>

          <div className="space-y-4 flex-1">
            <div className="p-4 rounded-xl border border-primary/20 bg-primary/5 flex flex-col gap-3">
              <div className="flex justify-between items-start">
                <span className="text-xs font-bold text-primary uppercase tracking-wider">CWE-89 SQLi</span>
                <span className="text-xs text-muted-foreground">auth.py</span>
              </div>
              <p className="text-sm text-white line-clamp-2">Model suggests using parameterized queries instead of f-strings.</p>
              <button className="mt-2 w-full py-2 bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 rounded-lg text-sm font-medium transition-colors">
                Review Fix
              </button>
            </div>
            
            <div className="p-4 rounded-xl border border-white/5 bg-white/[0.02] flex flex-col gap-3">
              <div className="flex justify-between items-start">
                <span className="text-xs font-bold text-white uppercase tracking-wider">CWE-79 XSS</span>
                <span className="text-xs text-muted-foreground">Header.tsx</span>
              </div>
              <p className="text-sm text-white line-clamp-2">Dangerous innerHTML usage detected. Model suggests sanitization.</p>
              <button className="mt-2 w-full py-2 bg-white/5 hover:bg-white/10 text-white border border-white/10 rounded-lg text-sm font-medium transition-colors">
                Review Fix
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}
