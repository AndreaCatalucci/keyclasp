"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Check, Copy, Terminal, Mail, ArrowRight } from "lucide-react";

function ActivateContent() {
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");
  const searchParams = useSearchParams();
  const router = useRouter();
  const sessionId = searchParams.get("session_id");

  useEffect(() => {
    if (!sessionId) {
      setError("No checkout session found. Please complete your purchase first.");
      setStatus("error");
      return;
    }

    fetch("/api/auth/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sessionId }),
    })
      .then(async (res) => {
        const data = await res.json();
        if (res.ok) {
          setEmail(data.email);
          setStatus("success");
        } else {
          setError(data.error || "Activation failed");
          setStatus("error");
        }
      })
      .catch(() => {
        setError("Connection failed. Please try again.");
        setStatus("error");
      });
  }, [sessionId]);

  const commands = [
    { label: "Install Keyblind CLI", cmd: "npm install -g keyblind" },
    { label: "Initialize your vault", cmd: "keyblind init" },
  ];

  if (status === "loading") {
    return (
      <div className="text-center">
        <Shield className="w-8 h-8 text-[#58a6ff] mx-auto mb-4 animate-pulse" />
        <p className="text-[#8b949e]">Verifying your purchase...</p>
      </div>
    );
  }

  if (status === "error") {
    return (
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-8 w-full max-w-md text-center">
        <Shield className="w-8 h-8 text-[#f85149] mx-auto mb-4" />
        <h1 className="text-lg font-semibold text-[#f0f6fc] mb-2">Activation Failed</h1>
        <p className="text-sm text-[#8b949e] mb-4">{error}</p>
        <a
          href="https://keyblind.dev"
          className="inline-block text-[#58a6ff] text-sm hover:underline"
        >
          Return to Keyblind
        </a>
      </div>
    );
  }

  return (
    <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-8 w-full max-w-2xl">
      <div className="text-center mb-8">
        <div className="w-12 h-12 bg-[#3fb950]/20 rounded-full flex items-center justify-center mx-auto mb-4">
          <Check className="w-6 h-6 text-[#3fb950]" />
        </div>
        <h1 className="text-xl font-semibold text-[#f0f6fc] mb-1">Purchase Complete</h1>
        <p className="text-sm text-[#8b949e]">
          {email ? `Pro license activated for ${email}` : "Pro license activated"}
        </p>
      </div>

      {/* Email notice — most important */}
      <div className="bg-[#1f6feb]/10 border border-[#1f6feb]/30 rounded-lg p-4 mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Mail className="w-5 h-5 text-[#58a6ff]" />
          <span className="text-sm font-medium text-[#58a6ff]">Check your email</span>
        </div>
        <p className="text-sm text-[#8b949e]">
          Your license key has been sent to <strong className="text-[#f0f6fc]">{email || "your email"}</strong>.
          Use it to activate Keyblind Pro in the CLI and sign into this dashboard.
        </p>
      </div>

      {/* Quick start */}
      <div className="bg-[#0d1117] border border-[#21262d] rounded-lg p-4 mb-6">
        <div className="flex items-center gap-2 mb-3">
          <Terminal className="w-4 h-4 text-[#8b949e]" />
          <span className="text-sm font-medium text-[#f0f6fc]">Quick Start</span>
        </div>
        <div className="space-y-2">
          {commands.map(({ label, cmd }) => (
            <div key={label} className="flex items-center justify-between bg-[#161b22] rounded px-3 py-2">
              <div>
                <p className="text-xs text-[#8b949e]">{label}</p>
                <code className="text-sm text-[#7ee787] font-mono">{cmd}</code>
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(cmd);
                  setCopied(cmd);
                  setTimeout(() => setCopied(""), 2000);
                }}
                className="p-1.5 hover:bg-[#21262d] rounded"
              >
                {copied === cmd ? (
                  <Check className="w-4 h-4 text-[#3fb950]" />
                ) : (
                  <Copy className="w-4 h-4 text-[#8b949e]" />
                )}
              </button>
            </div>
          ))}
          <div className="text-xs text-[#8b949e] px-3 py-2 bg-[#161b22] rounded">
            Then activate your license: <code className="text-[#f0f6fc]">keyblind activate &lt;key from email&gt;</code>
          </div>
        </div>
      </div>

      <div className="flex gap-3">
        <button
          onClick={() => router.push("/login")}
          className="flex items-center justify-center gap-1 flex-1 bg-[#1f6feb] text-white rounded-md py-2 text-sm font-medium hover:bg-[#1a5fd4]"
        >
          Sign In <ArrowRight className="w-3 h-3" />
        </button>
        <a
          href="https://keyblind.dev"
          target="_blank"
          rel="noopener"
          className="flex items-center gap-1 justify-center flex-1 border border-[#30363d] text-[#c9d1d9] rounded-md py-2 text-sm hover:bg-[#21262d]"
        >
          Homepage
        </a>
      </div>
    </div>
  );
}

export default function ActivatePage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117] p-6">
      <Suspense
        fallback={
          <div className="text-center">
            <Shield className="w-8 h-8 text-[#58a6ff] mx-auto mb-4 animate-pulse" />
            <p className="text-[#8b949e]">Loading...</p>
          </div>
        }
      >
        <ActivateContent />
      </Suspense>
    </div>
  );
}
