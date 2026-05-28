"use client";

import { useEffect, useState } from "react";
import { KeyblindClient } from "@/lib/keyblind-client";

export function Header() {
  const [connected, setConnected] = useState(false);
  const [secretCount, setSecretCount] = useState(0);

  useEffect(() => {
    const client = new KeyblindClient();
    client.checkHealth().then(setConnected);
    client.getSecrets().then((s) => setSecretCount(s.length));
  }, []);

  return (
    <header className="h-12 border-b border-[#21262d] flex items-center justify-between px-6 bg-[#0d1117]">
      <div className="flex items-center gap-3">
        <span className={`w-2 h-2 rounded-full ${connected ? "bg-[#3fb950]" : "bg-[#f85149]"}`} />
        <span className="text-xs text-[#8b949e]">
          {connected ? "Connected" : "Disconnected"}
        </span>
      </div>
      <div className="flex items-center gap-4">
        <span className="text-xs text-[#8b949e]">{secretCount} secrets</span>
      </div>
    </header>
  );
}
