import Link from "next/link";
import { Shield } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117] p-4">
      <div className="text-center max-w-sm">
        <Shield className="w-10 h-10 text-[#58a6ff] mx-auto mb-4" />
        <h1 className="text-lg font-semibold text-[#f0f6fc] mb-2">Page not found</h1>
        <p className="text-sm text-[#8b949e] mb-6">The page you're looking for doesn't exist or was moved.</p>
        <Link
          href="/"
          className="inline-block bg-[#1f6feb] text-white rounded-md px-4 py-2 text-sm font-medium hover:bg-[#1a5fd4]"
        >
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
