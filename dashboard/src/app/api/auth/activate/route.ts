import { NextResponse } from "next/server";
import { createSessionToken } from "@/lib/auth";

export async function POST(req: Request) {
  try {
    const { sessionId } = await req.json();

    if (!sessionId || typeof sessionId !== "string") {
      return NextResponse.json({ error: "Session ID is required" }, { status: 400 });
    }

    // Verify the Stripe checkout session
    const stripeKey = process.env.STRIPE_SECRET_KEY;
    if (!stripeKey) {
      return NextResponse.json(
        { error: "Stripe not configured. Set STRIPE_SECRET_KEY environment variable." },
        { status: 500 }
      );
    }

    const stripeRes = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
      headers: { Authorization: `Bearer ${stripeKey}` },
    });

    if (!stripeRes.ok) {
      return NextResponse.json({ error: "Invalid checkout session" }, { status: 400 });
    }

    const session = await stripeRes.json();

    // Validate session status
    if (session.payment_status !== "paid") {
      return NextResponse.json({ error: "Payment not completed" }, { status: 400 });
    }

    const email = session.customer_details?.email;
    if (!email) {
      return NextResponse.json({ error: "No email found in checkout session" }, { status: 400 });
    }

    // TODO: Generate and return a Keyblind license key for this email
    // For now, return success with instructions
    const token = await createSessionToken({
      email,
      tier: "pro",
      licenseId: sessionId,
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10),
    });

    const res = NextResponse.json({
      success: true,
      email,
      message: "Purchase verified. Install Keyblind CLI and activate your license.",
    });

    res.cookies.set("keyblind_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24,
    });

    return res;
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Server error" }, { status: 500 });
  }
}
