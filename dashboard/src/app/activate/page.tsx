"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Check, Copy, Terminal, ArrowRight } from "lucide-react";

function ActivateContent() {
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [email, setEmail] = useState("");
  const [licenseKey, setLicenseKey] = useState("");
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
          setLicenseKey(data.licenseKey || "");
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
    { label: "Activate your license", cmd: licenseKey ? `keyblind activate ${licenseKey}` : "" },
    { label: "Initialize your vault", cmd: "keyblind init" },
    { label: "Start the server", cmd: "keyblind start --http" },
    { label: "Sign into dashboard", cmd: "keyblind dashboard-login" },
  ].filter((c) => c.cmd);

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
        <div className="flex gap-3 justify-center">
          <button
            onClick={() => window.location.reload()}
            className="bg-[#1f6feb] text-white rounded-md px-4 py-2 text-sm font-medium hover:bg-[#1a5fd4]"
          >
            Try Again
          </button>
          <a
            href="https://keyblind.dev"
            className="border border-[#30363d] text-[#c9d1d9] rounded-md px-4 py-2 text-sm hover:bg-[#21262d]"
          >
            Return to Keyblind
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-8 w-full max-w-2xl">
      <div className="text-center mb-6">
        <div className="w-12 h-12 bg-[#3fb950]/20 rounded-full flex items-center justify-center mx-auto mb-4">
          <Check className="w-6 h-6 text-[#3fb950]" />
        </div>
        <h1 className="text-xl font-semibold text-[#f0f6fc] mb-1">Purchase Complete</h1>
        <p className="text-sm text-[#8b949e]">
          {email ? `Pro license for ${email}` : "Pro license activated"}
        </p>
      </div>

      {/* License Key Card */}
      {licenseKey && (
        <div className="bg-[#0d1117] border border-[#1f6feb]/30 rounded-lg p-4 mb-6">
          <p className="text-xs text-[#8b949e] mb-2">Your license key</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-sm text-[#7ee787] font-mono break-all bg-[#161b22] rounded px-3 py-2">
              {licenseKey}
            </code>
            <button
              onClick={() => {
                navigator.clipboard.writeText(licenseKey);
                setCopied("key");
                setTimeout(() => setCopied(""), 2000);
              }}
              className="p-2 hover:bg-[#21262d] rounded shrink-0"
              title="Copy license key"
            >
              {copied === "key" ? (
                <Check className="w-4 h-4 text-[#3fb950]" />
              ) : (
                <Copy className="w-4 h-4 text-[#8b949e]" />
              )}
            </button>
          </div>
          <p className="text-xs text-[#8b949e] mt-2">
            Also sent to your email. Save this key — you&apos;ll need it to sign into the dashboard.
          </p>
        </div>
      )}

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
                <code className="text-sm text-[#7ee787] font-mono break-all">{cmd}</code>
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(cmd);
                  setCopied(cmd);
                  setTimeout(() => setCopied(""), 2000);
                }}
                className="p-1.5 hover:bg-[#21262d] rounded shrink-0 ml-2"
              >
                {copied === cmd ? (
                  <Check className="w-4 h-4 text-[#3fb950]" />
                ) : (
                  <Copy className="w-4 h-4 text-[#8b949e]" />
                )}
              </button>
            </div>
          ))}
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
