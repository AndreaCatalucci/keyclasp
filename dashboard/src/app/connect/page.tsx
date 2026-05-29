"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Shield, Loader2, CheckCircle, XCircle } from "lucide-react";

function ConnectForm() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<"connecting" | "success" | "error">("connecting");
  const [errorMsg, setErrorMsg] = useState("");
  const [retries, setRetries] = useState(0);
  const maxRetries = 3;

  useEffect(() => {
    const token = searchParams.get("token");
    const port = searchParams.get("port") || "3100";

    if (!token) {
      setStatus("error");
      setErrorMsg("No pairing token found in URL");
      return;
    }

    let cancelled = false;

    async function verify() {
      try {
        const res = await fetch(`http://localhost:${port}/api/auth/pair`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.error || "Pairing verification failed");
        }

        const data = await res.json();

        const loginRes = await fetch("/api/auth/pair", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tier: data.tier, email: data.email }),
        });

        if (!loginRes.ok) throw new Error("Session creation failed");

        if (!cancelled) {
          setStatus("success");
          setTimeout(() => {
            window.location.href = "/";
          }, 1000);
        }
      } catch (err: any) {
        if (cancelled) return;
        const msg = err.message || "Failed to connect. Is Keyblind running?";
        setStatus("error");
        setErrorMsg(msg);

        // Auto-retry on network errors (server not running)
        if (retries < maxRetries && (msg.includes("Failed to fetch") || msg.includes("NetworkError"))) {
          const delay = Math.pow(2, retries) * 1000;
          setTimeout(() => {
            setStatus("connecting");
            setRetries((r) => r + 1);
          }, delay);
        }
      }
    }

    verify();
    return () => { cancelled = true; };
  }, [searchParams, router, retries]);

  function handleRetry() {
    setStatus("connecting");
    setErrorMsg("");
    setRetries((r) => r + 1);
  }

  return (
    <>
      {status === "connecting" && (
        <>
          <Loader2 className="w-8 h-8 text-[#58a6ff] mx-auto mb-4 animate-spin" />
          <h1 className="text-lg font-semibold text-[#f0f6fc]">Connecting to Keyblind...</h1>
          <p className="text-sm text-[#8b949e] mt-2">
            {retries > 0 ? `Retrying (attempt ${retries}/${maxRetries})...` : "Verifying your local vault"}
          </p>
        </>
      )}

      {status === "success" && (
        <>
          <CheckCircle className="w-8 h-8 text-[#3fb950] mx-auto mb-4" />
          <h1 className="text-lg font-semibold text-[#f0f6fc]">Connected</h1>
          <p className="text-sm text-[#8b949e] mt-2">Taking you to your dashboard...</p>
        </>
      )}

      {status === "error" && (
        <>
          <XCircle className="w-8 h-8 text-[#f85149] mx-auto mb-4" />
          <h1 className="text-lg font-semibold text-[#f0f6fc]">Connection Failed</h1>
          <p className="text-sm text-[#8b949e] mt-2">{errorMsg}</p>
          <p className="text-xs text-[#484f58] mt-4">
            Make sure Keyblind is running: <code className="text-[#7ee787]">keyblind start --http</code>
          </p>
          <div className="flex gap-2 justify-center mt-4">
            <button
              onClick={handleRetry}
              className="text-sm bg-[#1f6feb] text-white rounded-md px-4 py-1.5 hover:bg-[#1a5fd4]"
            >
              Retry
            </button>
            <button
              onClick={() => router.push("/login")}
              className="text-sm text-[#58a6ff] hover:text-[#79b8ff]"
            >
              Try license key instead
            </button>
          </div>
        </>
      )}
    </>
  );
}

export default function ConnectPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117] p-4">
      <div className="w-full max-w-sm text-center">
        <a href="https://keyblind.dev">
          <Shield className="w-10 h-10 text-[#58a6ff] mx-auto mb-3" />
        </a>

        <Suspense
          fallback={
            <>
              <Loader2 className="w-8 h-8 text-[#58a6ff] mx-auto mb-4 animate-spin" />
              <h1 className="text-lg font-semibold text-[#f0f6fc]">Loading...</h1>
            </>
          }
        >
          <ConnectForm />
        </Suspense>
      </div>
    </div>
  );
}
