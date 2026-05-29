"use client";

import { useState, useEffect } from "react";
import { KeyblindClient, type TOTPConfig } from "@/lib/keyblind-client";
import { Plus, Trash2, Copy, RefreshCw, Key, Clock } from "lucide-react";

export default function TOTPPage() {
  const [configs, setConfigs] = useState<TOTPConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState("");
  const [newUri, setNewUri] = useState("");
  const [error, setError] = useState("");
  const [codes, setCodes] = useState<Record<string, { code: string; remainingSeconds: number }>>({});
  const [codeTimers, setCodeTimers] = useState<Record<string, number>>({});
  const client = new KeyblindClient();

  async function loadConfigs() {
    try {
      const list = await client.getTOTPConfigs();
      setConfigs(list);
    } catch {
      setError("Failed to load TOTP configs. Is the server running?");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadConfigs(); }, []);

  // Update countdown timers
  useEffect(() => {
    const interval = setInterval(() => {
      setCodeTimers((prev) => {
        const next: Record<string, number> = {};
        for (const [name, t] of Object.entries(prev)) {
          if (t > 0) next[name] = t - 1;
        }
        return next;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    try {
      await client.storeTOTP(newName, newUri);
      setNewName("");
      setNewUri("");
      setShowAdd(false);
      await loadConfigs();
    } catch (err: any) {
      setError(err.message || "Failed to store TOTP config");
    }
  }

  async function handleGetCode(name: string) {
    try {
      const result = await client.getTOTPCode(name);
      setCodes((prev) => ({ ...prev, [name]: result }));
      setCodeTimers((prev) => ({ ...prev, [name]: result.remainingSeconds }));
    } catch (err: any) {
      setError(err.message || "Failed to generate code");
    }
  }

  async function handleCopy(name: string) {
    const code = codes[name]?.code;
    if (code) await navigator.clipboard.writeText(code);
  }

  async function handleDelete(name: string) {
    try {
      await client.deleteTOTP(name);
      await loadConfigs();
    } catch (err: any) {
      setError(err.message || "Failed to delete TOTP config");
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold">TOTP (2FA Codes)</h1>
        <div className="flex gap-2">
          <button onClick={loadConfigs} className="p-2 hover:bg-[#21262d] rounded-md" title="Refresh">
            <RefreshCw className="w-4 h-4 text-[#8b949e]" />
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 bg-[#1f6feb] text-white px-3 py-1.5 rounded-md text-sm hover:bg-[#1a5fd4]"
          >
            <Plus className="w-4 h-4" /> Add TOTP
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-[rgba(248,81,73,0.1)] border border-[#f85149] text-[#f85149] text-sm rounded-md p-3 mb-4">
          {error}
          <button onClick={() => setError("")} className="float-right">&times;</button>
        </div>
      )}

      {showAdd && (
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4 mb-4">
          <form onSubmit={handleAdd}>
            <input
              type="text" placeholder="Name (e.g. GitHub)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-2 focus:outline-none focus:border-[#58a6ff]"
            />
            <input
              type="text" placeholder="otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
              value={newUri}
              onChange={(e) => setNewUri(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-3 focus:outline-none focus:border-[#58a6ff] font-mono text-xs"
            />
            <div className="flex gap-2">
              <button type="submit" className="bg-[#1f6feb] text-white px-4 py-1.5 rounded-md text-sm">Save</button>
              <button type="button" onClick={() => setShowAdd(false)} className="text-[#8b949e] text-sm px-4 py-1.5">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-[#8b949e]">Loading...</p>
      ) : configs.length === 0 ? (
        <div className="text-center py-12 text-[#8b949e]">
          <Key className="w-8 h-8 mx-auto mb-3 opacity-50" />
          <p>No TOTP configs stored yet.</p>
          <p className="text-sm mt-1">Add one using an otpauth:// URI from your 2FA setup.</p>
        </div>
      ) : (
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#21262d]">
                <th className="text-left p-3 text-[#8b949e] font-medium">Name</th>
                <th className="text-left p-3 text-[#8b949e] font-medium">Issuer / Account</th>
                <th className="text-center p-3 text-[#8b949e] font-medium">Code</th>
                <th className="text-right p-3 text-[#8b949e] font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {configs.map((cfg) => (
                <tr key={cfg.name} className="border-b border-[#21262d] last:border-0 hover:bg-[#21262d]/50">
                  <td className="p-3 font-mono text-xs">{cfg.name}</td>
                  <td className="p-3 text-xs text-[#8b949e]">
                    {cfg.issuer && <span className="text-[#c9d1d9]">{cfg.issuer}</span>}
                    {cfg.account && <span> — {cfg.account}</span>}
                  </td>
                  <td className="p-3 text-center">
                    {codes[cfg.name] ? (
                      <div className="flex items-center justify-center gap-2">
                        <span className="font-mono text-lg font-bold text-[#3fb950] tracking-widest">
                          {codes[cfg.name].code}
                        </span>
                        <span className="text-xs text-[#8b949e]">
                          {codeTimers[cfg.name] ?? codes[cfg.name].remainingSeconds}s
                        </span>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleGetCode(cfg.name)}
                        className="flex items-center gap-1 text-xs text-[#58a6ff] hover:text-[#79b8ff]"
                      >
                        <Clock className="w-3 h-3" /> Generate
                      </button>
                    )}
                  </td>
                  <td className="p-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {codes[cfg.name] && (
                        <button onClick={() => handleCopy(cfg.name)} className="p-1.5 hover:bg-[#30363d] rounded" title="Copy code">
                          <Copy className="w-3.5 h-3.5 text-[#8b949e]" />
                        </button>
                      )}
                      <button onClick={() => handleDelete(cfg.name)} className="p-1.5 hover:bg-[#30363d] rounded" title="Delete">
                        <Trash2 className="w-3.5 h-3.5 text-[#f85149]" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
