"use client";

import { useState, useEffect } from "react";
import { KeyblindClient } from "@/lib/keyblind-client";

export default function AuditPage() {
  const [entries, setEntries] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const client = new KeyblindClient();

  useEffect(() => {
    client.getAuditLog(50).then(setEntries).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <h1 className="text-xl font-semibold mb-6">Audit Log</h1>
      {loading ? (
        <p className="text-sm text-[#8b949e]">Loading...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-[#8b949e]">No audit entries yet. Activity will appear here.</p>
      ) : (
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#21262d]">
                <th className="text-left p-3 text-[#8b949e] font-medium">Timestamp</th>
                <th className="text-left p-3 text-[#8b949e] font-medium">Action</th>
                <th className="text-left p-3 text-[#8b949e] font-medium">Secret</th>
                <th className="text-left p-3 text-[#8b949e] font-medium">Client</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry, i) => (
                <tr key={i} className="border-b border-[#21262d] last:border-0">
                  <td className="p-3 text-xs text-[#8b949e]">{entry.timestamp}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      entry.action === "resolve" ? "bg-[#1f6feb]/20 text-[#58a6ff]" :
                      entry.action === "store" ? "bg-[#3fb950]/20 text-[#3fb950]" :
                      "bg-[#f85149]/20 text-[#f85149]"
                    }`}>{entry.action}</span>
                  </td>
                  <td className="p-3 font-mono text-xs">{entry.secretName}</td>
                  <td className="p-3 text-xs text-[#8b949e]">{entry.clientInfo || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
