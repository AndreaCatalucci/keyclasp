"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";

export default function LoginPage() {
  const [licenseKey, setLicenseKey] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ licenseKey }),
      });
      if (res.ok) {
        router.push("/");
      } else {
        const data = await res.json();
        setError(data.error || "Invalid license key");
      }
    } catch {
      setError("Connection failed. Is the Keyblind server running?");
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117]">
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-8 w-full max-w-sm">
        <div className="flex items-center gap-2 mb-6 justify-center">
          <Shield className="w-6 h-6 text-[#58a6ff]" />
          <h1 className="text-lg font-semibold text-[#58a6ff]">Keyblind</h1>
        </div>
        <form onSubmit={handleSubmit}>
          <label className="block text-sm text-[#8b949e] mb-1">License Key</label>
          <input
            type="text"
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            placeholder="keyblind_pro_..."
            className="w-full bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff] mb-4"
          />
          {error && <p className="text-xs text-[#f85149] mb-3">{error}</p>}
          <button
            type="submit"
            className="w-full bg-[#1f6feb] text-white rounded-md py-2 text-sm font-medium hover:bg-[#1a5fd4] transition-colors"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
}
