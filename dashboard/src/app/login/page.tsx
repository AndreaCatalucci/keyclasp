"use client";

import { Suspense } from "react";
import { Shield, Terminal } from "lucide-react";

function LoginForm() {
  return (
    <div>
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-6">
        <div className="flex items-center gap-2 mb-3">
          <Terminal className="w-4 h-4 text-[#58a6ff]" />
          <h2 className="text-sm font-semibold text-[#f0f6fc]">Connect with CLI</h2>
        </div>
        <p className="text-xs text-[#8b949e] mb-3">
          Run this command in your terminal to sign in instantly:
        </p>
        <code className="block bg-[#0d1117] border border-[#21262d] rounded-md px-3 py-2.5 text-sm text-[#7ee787] font-mono mb-3 select-all">
          keyblind dashboard-login
        </code>
        <p className="text-xs text-[#484f58]">
          Opens a one-time link. Keyblind must be running with{" "}
          <code className="text-[#8b949e]">keyblind start --http</code>.
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117] p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <a href="https://keyblind.dev" className="inline-block">
            <Shield className="w-10 h-10 text-[#58a6ff] mx-auto mb-3" />
            <h1 className="text-xl font-semibold text-[#f0f6fc]">Keyblind</h1>
          </a>
          <p className="text-sm text-[#8b949e] mt-1">Sign in to your dashboard</p>
        </div>

        <Suspense
          fallback={
            <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-6 text-center">
              <p className="text-sm text-[#8b949e]">Loading...</p>
            </div>
          }
        >
          <LoginForm />
        </Suspense>
      </div>
    </div>
  );
}
