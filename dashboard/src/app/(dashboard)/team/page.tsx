"use client";

import { useState, useEffect } from "react";
import { KeyblindClient, KeyblindClientError } from "@/lib/keyblind-client";
import { Shield, Plus, Download, Trash2, Key, Eye, EyeOff, AlertTriangle } from "lucide-react";

export default function TeamPage() {
  const [passphrase, setPassphrase] = useState("");
  const [savedPassphrase, setSavedPassphrase] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [secrets, setSecrets] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [pushName, setPushName] = useState("");
  const [pushValue, setPushValue] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [vaultPath, setVaultPath] = useState("");

  const client = new KeyblindClient();

  async function handleInit() {
    if (!passphrase) return;
    setError("");
    setLoading(true);
    try {
      const result = await client.teamInit(passphrase);
      setVaultPath(result.path);
      setSavedPassphrase(passphrase);
      setAuthenticated(true);
      setSecrets([]);
    } catch (err: any) {
      setError(err.message || "Failed to initialize team vault");
    } finally {
      setLoading(false);
    }
  }

  async function handleList() {
    if (!savedPassphrase) return;
    setError("");
    setLoading(true);
    try {
      const names = await client.teamList(savedPassphrase);
      setSecrets(names);
      setAuthenticated(true);
    } catch (err: any) {
      if (err instanceof KeyblindClientError && err.status === 400) {
        setError("Invalid passphrase or vault not found. Try initializing first.");
      } else {
        setError(err.message || "Failed to list team secrets");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handlePush(e: React.FormEvent) {
    e.preventDefault();
    if (!pushName || !savedPassphrase) return;
    setError("");
    setLoading(true);
    try {
      await client.teamPush(pushName, savedPassphrase, pushValue || undefined);
      setPushName("");
      setPushValue("");
      await handleList();
    } catch (err: any) {
      setError(err.message || "Failed to push secret");
    } finally {
      setLoading(false);
    }
  }

  async function handlePull() {
    if (!savedPassphrase) return;
    setError("");
    setLoading(true);
    try {
      const result = await client.teamPull(savedPassphrase);
      setError(`Imported ${result.imported} secrets into local vault`);
    } catch (err: any) {
      setError(err.message || "Failed to pull secrets");
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(name: string) {
    if (!savedPassphrase) return;
    setError("");
    try {
      await client.teamDelete(name, savedPassphrase);
      setSecrets((prev) => prev.filter((s) => s !== name));
    } catch (err: any) {
      setError(err.message || "Failed to delete secret");
    }
  }

  // List on mount if we have a saved passphrase
  useEffect(() => {
    if (savedPassphrase) handleList();
  }, []);

  // Auth screen
  if (!authenticated) {
    return (
      <div>
        <h1 className="text-xl font-semibold mb-6">Team Vault</h1>
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-6 max-w-md">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-[#58a6ff]" />
            <h2 className="text-sm font-semibold text-[#f0f6fc]">Access Team Vault</h2>
          </div>
          <p className="text-xs text-[#8b949e] mb-4">
            Enter your team vault passphrase. If this is your first time, a new vault will be created.
          </p>

          <div className="relative mb-3">
            <input
              type={showPassphrase ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Team vault passphrase"
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 pr-10 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff]"
              onKeyDown={(e) => e.key === "Enter" && handleList()}
            />
            <button
              onClick={() => setShowPassphrase(!showPassphrase)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[#8b949e] hover:text-[#c9d1d9]"
            >
              {showPassphrase ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          {error && (
            <p className="text-xs text-[#f85149] mb-3 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> {error}
            </p>
          )}

          <div className="flex gap-2">
            <button
              onClick={handleList}
              disabled={loading || !passphrase}
              className="flex-1 bg-[#1f6feb] text-white rounded-md py-2 text-sm font-medium hover:bg-[#1a5fd4] disabled:opacity-50"
            >
              {loading ? "..." : "Unlock"}
            </button>
            <button
              onClick={handleInit}
              disabled={loading || !passphrase}
              className="flex-1 border border-[#30363d] text-[#c9d1d9] rounded-md py-2 text-sm hover:bg-[#21262d] disabled:opacity-50"
            >
              Init New
            </button>
          </div>

          <p className="text-xs text-[#484f58] mt-3">
            Team vaults are stored in <code className="text-[#8b949e]">.keyblind/team.vault</code> and can be
            committed to git for sharing.
          </p>
        </div>
      </div>
    );
  }

  // Authenticated view
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold">Team Vault</h1>
          <p className="text-xs text-[#8b949e] mt-1">
            {vaultPath || ".keyblind/team.vault"} &middot; {secrets.length} secrets
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handlePull}
            disabled={loading}
            className="flex items-center gap-1 border border-[#30363d] text-[#c9d1d9] rounded-md px-3 py-1.5 text-xs hover:bg-[#21262d]"
          >
            <Download className="w-3.5 h-3.5" /> Pull All
          </button>
        </div>
      </div>

      {error && (
        <div
          className={`text-xs mb-4 p-3 rounded-md flex items-center gap-1 ${
            error.startsWith("Imported")
              ? "bg-[#3fb950]/10 border border-[#3fb950]/30 text-[#3fb950]"
              : "bg-[#f85149]/10 border border-[#f85149]/30 text-[#f85149]"
          }`}
        >
          {error}
          <button onClick={() => setError("")} className="ml-auto text-[#8b949e]">x</button>
        </div>
      )}

      {/* Add secret form */}
      <form onSubmit={handlePush} className="bg-[#161b22] border border-[#21262d] rounded-lg p-4 mb-4">
        <div className="flex gap-2">
          <input
            type="text"
            value={pushName}
            onChange={(e) => setPushName(e.target.value)}
            placeholder="Secret name"
            className="flex-1 bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-1.5 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff]"
          />
          <input
            type="text"
            value={pushValue}
            onChange={(e) => setPushValue(e.target.value)}
            placeholder="Value (or pull from local vault)"
            className="flex-[2] bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-1.5 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff]"
          />
          <button
            type="submit"
            disabled={loading || !pushName}
            className="flex items-center gap-1 bg-[#1f6feb] text-white rounded-md px-3 py-1.5 text-xs font-medium hover:bg-[#1a5fd4] disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" /> Push
          </button>
        </div>
      </form>

      {/* Secrets list */}
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg overflow-hidden">
        {secrets.length === 0 ? (
          <div className="p-8 text-center">
            <Key className="w-6 h-6 text-[#484f58] mx-auto mb-2" />
            <p className="text-sm text-[#8b949e]">No secrets in team vault</p>
            <p className="text-xs text-[#484f58] mt-1">
              Push secrets from your local vault or add new ones above.
            </p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#21262d]">
                <th className="text-left px-4 py-2 text-xs text-[#8b949e] font-medium">Name</th>
                <th className="text-right px-4 py-2 text-xs text-[#8b949e] font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {secrets.map((name) => (
                <tr key={name} className="border-b border-[#21262d] last:border-0 hover:bg-[#0d1117]">
                  <td className="px-4 py-2.5">
                    <code className="text-sm text-[#c9d1d9]">{name}</code>
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      onClick={() => handleDelete(name)}
                      className="p-1.5 text-[#8b949e] hover:text-[#f85149] rounded hover:bg-[#21262d]"
                      title="Delete from team vault"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-[#484f58] mt-4">
        Team vaults use AES-256-GCM encryption with PBKDF2 key derivation (600k iterations). Share the
        passphrase with your team and commit <code className="text-[#8b949e]">.keyblind/team.vault</code> to git.
      </p>
    </div>
  );
}
