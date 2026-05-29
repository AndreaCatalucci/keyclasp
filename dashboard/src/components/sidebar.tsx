"use client";

import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { Key, Shield, Clock, Users, FileText, LogOut, Smartphone, Send, Skull } from "lucide-react";
import { KeyblindClient } from "@/lib/keyblind-client";

const navItems = [
  { href: "/", label: "Overview", icon: Shield },
  { href: "/secrets", label: "Secrets", icon: Key },
  { href: "/totp", label: "TOTP", icon: Smartphone },
  { href: "/share", label: "Share", icon: Send },
  { href: "/deadman", label: "Dead Man", icon: Skull },
  { href: "/audit", label: "Audit Log", icon: Clock },
  { href: "/team", label: "Team", icon: Users },
  { href: "/license", label: "License", icon: FileText },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    const client = new KeyblindClient();
    let active = true;

    async function check() {
      const ok = await client.checkHealth();
      if (active) setConnected(ok);
    }

    check();
    const interval = setInterval(check, 15000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  async function handleSignOut() {
    await fetch("/api/auth/signout", { method: "POST" });
    router.push("/login");
  }

  return (
    <aside className="w-56 bg-[#161b22] border-r border-[#21262d] flex flex-col min-h-screen">
      <div className="p-4 border-b border-[#21262d]">
        <Link href="/" className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-[#58a6ff]" />
          <span className="font-semibold text-[#58a6ff] text-sm">Keyblind</span>
        </Link>
      </div>
      <nav className="flex-1 p-3">
        {navItems.map((item) => {
          const active = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm mb-1 transition-colors ${
                active
                  ? "bg-[#1f6feb] text-white"
                  : "text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d]"
              }`}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-3 border-t border-[#21262d] space-y-1">
        <div className="flex items-center gap-2 px-3 py-1.5 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${
              connected === null
                ? "bg-[#484f58]"
                : connected
                ? "bg-[#3fb950]"
                : "bg-[#f85149]"
            }`}
          />
          <span className="text-[#8b949e]">
            {connected === null ? "Checking..." : connected ? "Connected" : "Disconnected"}
          </span>
        </div>
        <button
          onClick={handleSignOut}
          className="flex items-center gap-3 px-3 py-2 rounded-md text-sm text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d] w-full transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
