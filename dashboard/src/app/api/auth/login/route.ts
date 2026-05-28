import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const { licenseKey } = await req.json();
    // Basic validation — in production, validate against Stripe + Ed25519
    if (!licenseKey || licenseKey.length < 20) {
      return NextResponse.json({ error: "Invalid license key" }, { status: 401 });
    }

    const res = NextResponse.json({ success: true, tier: "pro" });
    res.cookies.set("keyblind_token", "session-" + Date.now(), {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 60 * 60 * 24, // 24h
    });
    return res;
  } catch {
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
