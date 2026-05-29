export default function LicensePage() {
  return (
    <div>
      <h1 className="text-xl font-semibold mb-6">License</h1>
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-6">
        <div className="space-y-3">
          <div className="flex justify-between">
            <span className="text-sm text-[#8b949e]">Tier</span>
            <span className="text-sm font-medium text-[#3fb950]">Pro</span>
          </div>
          <div className="flex justify-between">
            <span className="text-sm text-[#8b949e]">Email</span>
            <span className="text-sm text-[#c9d1d9]">—</span>
          </div>
          <div className="flex justify-between">
            <span className="text-sm text-[#8b949e]">Expires</span>
            <span className="text-sm text-[#c9d1d9]">—</span>
          </div>
        </div>
        <div className="mt-4 pt-4 border-t border-[#21262d]">
          <a
            href="https://keyblind.dev/pricing"
            className="inline-block bg-[#1f6feb] text-white px-4 py-2 rounded-md text-sm hover:bg-[#1a5fd4]"
          >
            Upgrade
          </a>
        </div>
      </div>
    </div>
  );
}
