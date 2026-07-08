import { KeyblindClient } from "@/lib/keyblind-client";

async function getStats() {
  try {
    const client = new KeyblindClient();
    const secrets = await client.getSecrets();
    const auditLog = await client.getAuditLog(5);
    return { secretCount: secrets.length, recentActivity: auditLog };
  } catch {
    return { secretCount: 0, recentActivity: [] };
  }
}

export default async function Home() {
  const stats = await getStats();

  return (
    <div>
      <h1 className="text-xl font-semibold mb-6">Dashboard</h1>
      <div className="grid grid-cols-2 gap-4 mb-8">
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4">
          <p className="text-sm text-[#8b949e]">Secrets</p>
          <p className="text-2xl font-bold text-[#58a6ff]">{stats.secretCount}</p>
        </div>
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4">
          <p className="text-sm text-[#8b949e]">Status</p>
          <p className="text-lg font-bold text-[#3fb950]">Connected</p>
        </div>
      </div>

      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4">
        <h2 className="text-sm font-semibold mb-3 text-[#8b949e]">Recent Activity</h2>
        {stats.recentActivity.length === 0 ? (
          <p className="text-sm text-[#8b949e]">No recent activity</p>
        ) : (
          <div className="space-y-2">
            {stats.recentActivity.map((entry: any, i: number) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <span className="text-[#8b949e] text-xs w-16">{entry.timestamp?.slice(0, 16)}</span>
                <span className="bg-[#21262d] px-2 py-0.5 rounded text-xs">{entry.action}</span>
                <span className="text-[#c9d1d9]">{entry.secretName}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
