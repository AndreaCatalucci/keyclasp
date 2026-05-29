"use client";

import { useState, useEffect } from "react";
import { KeyblindClient } from "@/lib/keyblind-client";
import { Send, Download, Copy, Check } from "lucide-react";

export default function SharePage() {
  const [secrets, setSecrets] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Create share
  const [shareName, setShareName] = useState("");
  const [ttl, setTtl] = useState("24h");
  const [maxViews, setMaxViews] = useState("");
  const [shareLink, setShareLink] = useState("");

  // Receive share
  const [fragment, setFragment] = useState("");
  const [targetName, setTargetName] = useState("");

  const client = new KeyblindClient();

  useEffect(() => {
    client.getSecrets().then(setSecrets).catch(() => {}).finally(() => setLoading(false));
  }, []);

  async function handleCreateShare(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSuccess("");
    try {
      const result = await client.createShareLink(shareName, {
        ttl: ttl || undefined,
        maxViews: maxViews ? parseInt(maxViews) : undefined,
      });
      setShareLink(result.url);
      setSuccess("Share link created!");
    } catch (err: any) {
      setError(err.message || "Failed to create share link");
    }
  }

  async function handleReceive(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSuccess("");
    try {
      const result = await client.receiveShare(fragment, targetName || undefined);
      setSuccess(`Secret stored as "${result.received}"`);
      setFragment("");
      setTargetName("");
    } catch (err: any) {
      setError(err.message || "Failed to receive share");
    }
  }

  async function copyLink() {
    await navigator.clipboard.writeText(shareLink);
    setSuccess("Link copied to clipboard!");
  }

  return (
    <div>
      <h1 className="text-xl font-semibold mb-6">Secret Sharing</h1>

      {error && (
        <div className="bg-[rgba(248,81,73,0.1)] border border-[#f85149] text-[#f85149] text-sm rounded-md p-3 mb-4">
          {error}
          <button onClick={() => setError("")} className="float-right">&times;</button>
        </div>
      )}

      {success && (
        <div className="bg-[rgba(63,185,80,0.1)] border border-[#3fb950] text-[#3fb950] text-sm rounded-md p-3 mb-4">
          {success}
          <button onClick={() => setSuccess("")} className="float-right">&times;</button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Create Share */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4">
          <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Send className="w-4 h-4 text-[#58a6ff]" /> Create Share Link
          </h2>
          <form onSubmit={handleCreateShare}>
            <label className="block text-xs text-[#8b949e] mb-1">Secret to share</label>
            <select
              value={shareName}
              onChange={(e) => setShareName(e.target.value)}
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-3 focus:outline-none focus:border-[#58a6ff]"
            >
              <option value="">Select a secret...</option>
              {secrets.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>

            <div className="grid grid-cols-2 gap-3 mb-3">
              <div>
                <label className="block text-xs text-[#8b949e] mb-1">TTL (e.g. 24h, 7d)</label>
                <input
                  type="text" value={ttl}
                  onChange={(e) => setTtl(e.target.value)}
                  className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm focus:outline-none focus:border-[#58a6ff]"
                />
              </div>
              <div>
                <label className="block text-xs text-[#8b949e] mb-1">Max Views</label>
                <input
                  type="number" value={maxViews}
                  onChange={(e) => setMaxViews(e.target.value)}
                  placeholder="Unlimited"
                  className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm focus:outline-none focus:border-[#58a6ff]"
                />
              </div>
            </div>

            <button type="submit" className="bg-[#1f6feb] text-white px-4 py-1.5 rounded-md text-sm">Create Link</button>
          </form>

          {shareLink && (
            <div className="mt-4 p-3 bg-[#0d1117] border border-[#21262d] rounded-md">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs text-[#8b949e]">Share Link:</span>
                <button onClick={copyLink} className="p-1 hover:bg-[#21262d] rounded" title="Copy">
                  <Copy className="w-3 h-3 text-[#8b949e]" />
                </button>
              </div>
              <p className="font-mono text-xs text-[#7ee787] break-all">{shareLink}</p>
            </div>
          )}
        </div>

        {/* Receive Share */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4">
          <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Download className="w-4 h-4 text-[#3fb950]" /> Receive Shared Secret
          </h2>
          <form onSubmit={handleReceive}>
            <label className="block text-xs text-[#8b949e] mb-1">Share link or fragment</label>
            <input
              type="text" value={fragment}
              onChange={(e) => setFragment(e.target.value)}
              placeholder="Paste the full share link or fragment..."
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-3 focus:outline-none focus:border-[#58a6ff] font-mono text-xs"
            />

            <label className="block text-xs text-[#8b949e] mb-1">Store as (optional)</label>
            <input
              type="text" value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
              placeholder="Custom name for the secret"
              className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm mb-3 focus:outline-none focus:border-[#58a6ff]"
            />

            <button type="submit" className="bg-[#238636] text-white px-4 py-1.5 rounded-md text-sm">Receive Secret</button>
          </form>
        </div>
      </div>

      <div className="mt-6 bg-[#161b22] border border-[#21262d] rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-2 text-[#8b949e]">How It Works</h3>
        <p className="text-xs text-[#8b949e] leading-relaxed">
          Secrets are encrypted with AES-256-GCM and packed into the URL fragment (the part after #).
          The fragment is never sent to any server — only someone with the full link can decrypt it.
          Each link can be limited by time (TTL) or number of views.
        </p>
      </div>
    </div>
  );
}
