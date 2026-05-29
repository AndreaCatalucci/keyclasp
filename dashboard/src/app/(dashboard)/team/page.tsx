export default function TeamPage() {
  return (
    <div>
      <h1 className="text-xl font-semibold mb-6">Team</h1>
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-8 text-center">
        <p className="text-[#8b949e] mb-2">Team management requires a Team license.</p>
        <p className="text-sm text-[#8b949e]">
          Upgrade at <a href="https://keyblind.dev/pricing" className="text-[#58a6ff] hover:underline">keyblind.dev/pricing</a>
        </p>
      </div>
    </div>
  );
}
