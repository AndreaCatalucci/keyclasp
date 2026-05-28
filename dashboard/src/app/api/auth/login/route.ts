import { NextResponse } from "next/server";
import { createSessionToken } from "@/lib/auth";
import { verifyLicenseKey } from "@/lib/license";

export async function POST(req: Request) {
  try {
    const { licenseKey } = await req.json();

    if (!licenseKey || typeof licenseKey !== "string") {
      return NextResponse.json({ error: "License key is required" }, { status: 401 });
    }

    // Validate Ed25519-signed license key
    const info = verifyLicenseKey(licenseKey);
    if (!info) {
      return NextResponse.json({ error: "Invalid or expired license key" }, { status: 401 });
    }

    // Create JWT session
    const token = await createSessionToken({
      email: info.email,
      tier: info.tier,
      licenseId: info.id,
      expiresAt: info.exp,
    });

    const res = NextResponse.json({
      success: true,
      email: info.email,
      tier: info.tier,
    });

    res.cookies.set("keyblind_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24, // 24h
    });

    return res;
  } catch {
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
