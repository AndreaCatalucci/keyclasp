"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Key, Shield, Clock, Users, FileText, Settings } from "lucide-react";

const navItems = [
  { href: "/", label: "Overview", icon: Shield },
  { href: "/secrets", label: "Secrets", icon: Key },
  { href: "/audit", label: "Audit Log", icon: Clock },
  { href: "/team", label: "Team", icon: Users },
  { href: "/license", label: "License", icon: FileText },
];

export function Sidebar() {
  const pathname = usePathname();

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
    </aside>
  );
}
