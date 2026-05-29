"use client";

import { useState, useEffect } from "react";
import { KeyblindClient, type DeadmanStatus } from "@/lib/keyblind-client";
import { RefreshCw, ShieldCheck, ShieldAlert, ShieldOff } from "lucide-react";

export default function DeadmanPage() {
  const [status, setStatus] = useState<DeadmanStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [checkingIn, setCheckingIn] = useState(false);
  const client = new KeyblindClient();

  async function loadStatus() {
    try {
      const s = await client.getDeadmanStatus();
      setStatus(s);
    } catch {
      setError("Failed to load dead man's switch status. Is the server running?");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadStatus(); }, []);

  async function handleCheckin() {
    setCheckingIn(true);
    try {
      await client.deadmanCheckin();
      await loadStatus();
    } catch (err: any) {
      setError(err.message || "Check-in failed");
    } finally {
      setCheckingIn(false);
    }
  }

  if (loading) return <p className="text-sm text-[#8b949e]">Loading...</p>;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold">Dead Man's Switch</h1>
        <button onClick={loadStatus} className="p-2 hover:bg-[#21262d] rounded-md" title="Refresh">
          <RefreshCw className="w-4 h-4 text-[#8b949e]" />
        </button>
      </div>

      {error && (
        <div className="bg-[rgba(248,81,73,0.1)] border border-[#f85149] text-[#f85149] text-sm rounded-md p-3 mb-4">
          {error}
          <button onClick={() => setError("")} className="float-right">&times;</button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Status Card */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            {!status?.enabled ? (
              <ShieldOff className="w-8 h-8 text-[#484f58]" />
            ) : !status.triggered ? (
              <ShieldCheck className="w-8 h-8 text-[#3fb950]" />
            ) : (
              <ShieldAlert className="w-8 h-8 text-[#d29922]" />
            )}
            <div>
              <h2 className="text-lg font-semibold">
                {!status?.enabled ? "Not Configured" : !status.triggered ? "Active" : "Triggered"}
              </h2>
              <p className="text-xs text-[#8b949e]">
                {!status?.enabled
                  ? "Set up a dead man's switch via CLI"
                  : !status.triggered
                  ? "Switch is armed and monitoring"
                  : "Switch has been triggered"}
              </p>
            </div>
          </div>

          {status?.enabled && (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-[#8b949e]">Contact Email</span>
                <span className="font-mono text-xs">{status.contactEmail || "—"}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-[#8b949e]">Days Remaining</span>
                <span className={`font-mono font-bold ${(status.daysRemaining ?? 0) <= 3 ? "text-[#f85149]" : "text-[#3fb950]"}`}>
                  {status.daysRemaining ?? "—"} days
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-[#8b949e]">Last Check-in</span>
                <span className="font-mono text-xs">{status.lastCheckin || "—"}</span>
              </div>
            </div>
          )}
        </div>

        {/* Action Card */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-6 flex flex-col items-center justify-center text-center">
          {status?.enabled ? (
            <>
              <ShieldCheck className="w-12 h-12 text-[#3fb950] mb-4" />
              <h3 className="font-semibold mb-2">I'm Still Here</h3>
              <p className="text-sm text-[#8b949e] mb-4">
                Click below to reset the countdown timer. If you don't check in before the deadline, your designated contacts will be notified.
              </p>
              <button
                onClick={handleCheckin}
                disabled={checkingIn}
                className="bg-[#238636] text-white px-6 py-2.5 rounded-md text-sm font-semibold hover:bg-[#2ea043] disabled:opacity-50"
              >
                {checkingIn ? "Checking in..." : "Check In Now"}
              </button>
            </>
          ) : (
            <>
              <ShieldOff className="w-12 h-12 text-[#484f58] mb-4" />
              <h3 className="font-semibold mb-2">Not Set Up</h3>
              <p className="text-sm text-[#8b949e]">
                Run <code className="bg-[#0d1117] px-1.5 py-0.5 rounded text-xs text-[#7ee787]">keyblind deadman setup --days 30 --contact you@email.com</code> to configure your dead man's switch.
              </p>
            </>
          )}
        </div>
      </div>

      <div className="mt-6 bg-[#161b22] border border-[#21262d] rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-2 text-[#8b949e]">What Is a Dead Man's Switch?</h3>
        <p className="text-xs text-[#8b949e] leading-relaxed">
          If you don't check in within the configured period, your encrypted vault can be released to
          designated emergency contacts. This ensures your team or family can access critical credentials
          if you become unavailable.
        </p>
      </div>
    </div>
  );
}
