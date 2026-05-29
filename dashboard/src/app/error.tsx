"use client";

import { Shield } from "lucide-react";

export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117] p-4">
      <div className="text-center max-w-sm">
        <Shield className="w-10 h-10 text-[#f85149] mx-auto mb-4" />
        <h1 className="text-lg font-semibold text-[#f0f6fc] mb-2">Something went wrong</h1>
        <p className="text-sm text-[#8b949e] mb-6">An unexpected error occurred. Try again or return to the dashboard.</p>
        <div className="flex gap-3 justify-center">
          <button
            onClick={reset}
            className="bg-[#1f6feb] text-white rounded-md px-4 py-2 text-sm font-medium hover:bg-[#1a5fd4]"
          >
            Try Again
          </button>
          <a
            href="/"
            className="border border-[#30363d] text-[#c9d1d9] rounded-md px-4 py-2 text-sm hover:bg-[#21262d]"
          >
            Dashboard
          </a>
        </div>
      </div>
    </div>
  );
}
