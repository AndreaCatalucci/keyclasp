import { NextResponse } from "next/server";
import { createSessionToken } from "@/lib/auth";

export async function POST(req: Request) {
  try {
    await req.json(); // consume body (no fields needed post-license removal)

    const token = await createSessionToken(
      new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    );

    const res = NextResponse.json({ success: true });
    res.cookies.set("keyblind_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24,
    });

    return res;
  } catch {
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
