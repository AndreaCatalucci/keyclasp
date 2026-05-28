"use client";

import { useState, useEffect } from "react";
import { KeyblindClient } from "@/lib/keyblind-client";
import { Plus, Trash2, Copy, RefreshCw } from "lucide-react";

export default function SecretsPage() {
  const [secrets, setSecrets] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState("");
  const [newValue, setNewValue] = useState("");
  const [error, setError] = useState("");
  const client = new KeyblindClient();

  async function loadSecrets() {
    try {
      const names = await client.getSecrets();
      setSecrets(names);
    } catch {
      setError("Failed to load secrets. Is the server running?");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadSecrets(); }, []);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    try {
      await client.storeSecret(newName, newValue);
      setNewName("");
      setNewValue("");
      setShowAdd(false);
      await loadSecrets();
    } catch {
      setError("Failed to store secret");
    }
  }

  async function handleCopy(name: string) {
    try {
      const value = await client.getSecret(name);
      await navigator.clipboard.writeText(value);
    } catch {
      setError("Failed to copy secret");
    }
  }

  async function handleDelete(name: string) {
    try {
      await client.deleteSecret(name);
      await loadSecrets();
    } catch {
      setError("Failed to delete secret");
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold">Secrets</h1>
        <div className="flex gap-2">
          <button onClick={loadSecrets} className="p-2 hover:bg-[#21262d] rounded-md" title="Refresh">
            <RefreshCw className="w-4 h-4 text-[#8b949e]" />
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 bg-[#1f6feb] text-white px-3 py-1.5 rounded-md text-sm hover:bg-[#1a5fd4]"
          >
            <Plus className="w-4 h-4" /> Add Secret
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
              type="text" placeholder="SECRET_NAME"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-2 focus:outline-none focus:border-[#58a6ff]"
            />
            <input
              type="password" placeholder="Secret value"
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-3 focus:outline-none focus:border-[#58a6ff]"
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
      ) : secrets.length === 0 ? (
        <div className="text-center py-12 text-[#8b949e]">
          <p>No secrets stored yet.</p>
          <p className="text-sm mt-1">Click "Add Secret" to store your first one.</p>
        </div>
      ) : (
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#21262d]">
                <th className="text-left p-3 text-[#8b949e] font-medium">Name</th>
                <th className="text-right p-3 text-[#8b949e] font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {secrets.map((name) => (
                <tr key={name} className="border-b border-[#21262d] last:border-0 hover:bg-[#21262d]/50">
                  <td className="p-3 font-mono text-xs">{name}</td>
                  <td className="p-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={() => handleCopy(name)} className="p-1.5 hover:bg-[#30363d] rounded" title="Copy">
                        <Copy className="w-3.5 h-3.5 text-[#8b949e]" />
                      </button>
                      <button onClick={() => handleDelete(name)} className="p-1.5 hover:bg-[#30363d] rounded" title="Delete">
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
