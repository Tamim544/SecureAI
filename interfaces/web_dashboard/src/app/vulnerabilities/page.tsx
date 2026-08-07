"use client";

import { motion } from "framer-motion";
import { Shield, Search, Filter } from "lucide-react";

export default function Vulnerabilities() {
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
          <motion.h2 variants={itemVariants} className="text-3xl font-bold tracking-tight text-white mb-2 flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary" />
            Vulnerabilities Database
          </motion.h2>
          <motion.p variants={itemVariants} className="text-muted-foreground">
            Explore and search through the semantic knowledge graph of identified vulnerabilities.
          </motion.p>
        </div>
      </div>

      <motion.div variants={itemVariants} className="glass-card p-6">
        <div className="flex flex-col md:flex-row gap-4 mb-6">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <input 
              type="text" 
              placeholder="Semantic Search (e.g. 'find all SQL queries using string formatting')" 
              className="w-full bg-secondary/50 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
            />
          </div>
          <button className="px-6 py-3 bg-secondary/80 border border-white/10 rounded-xl flex items-center gap-2 hover:bg-secondary transition-colors text-white font-medium">
            <Filter className="w-4 h-4" /> Filters
          </button>
        </div>

        <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-white/10 rounded-xl bg-white/[0.01]">
          <Shield className="w-12 h-12 text-muted-foreground/30 mb-4" />
          <h3 className="text-xl font-medium text-white mb-1">Semantic Search Ready</h3>
          <p className="text-muted-foreground">Enter a query to search across the indexed code embeddings.</p>
        </div>
      </motion.div>
    </motion.div>
  );
}
