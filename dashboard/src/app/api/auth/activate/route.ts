import { NextResponse } from "next/server";
import { createSessionToken } from "@/lib/auth";
import { generateLicenseKey } from "@/lib/license-gen";

export async function POST(req: Request) {
  try {
    const { sessionId } = await req.json();

    if (!sessionId || typeof sessionId !== "string") {
      return NextResponse.json({ error: "Session ID is required" }, { status: 400 });
    }

    const stripeKey = process.env.STRIPE_SECRET_KEY;
    if (!stripeKey) {
      return NextResponse.json({ error: "Stripe not configured" }, { status: 500 });
    }

    const stripeRes = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
      headers: { Authorization: `Bearer ${stripeKey}` },
    });

    if (!stripeRes.ok) {
      return NextResponse.json({ error: "Invalid checkout session" }, { status: 400 });
    }

    const session = await stripeRes.json();

    if (session.payment_status !== "paid") {
      return NextResponse.json({ error: "Payment not completed" }, { status: 400 });
    }

    const email = session.customer_details?.email;
    if (!email) {
      return NextResponse.json({ error: "No email found in checkout session" }, { status: 400 });
    }

    const tier = session.metadata?.tier || "pro";
    const expYears = parseInt(session.metadata?.expiry_years || "1", 10);
    const expDate = new Date(Date.now() + expYears * 365 * 86400000).toISOString().slice(0, 10);

    // Generate license key deterministically from session ID
    const licenseKey = generateLicenseKey(tier, email, expDate, sessionId);

    // Email is sent by the Stripe webhook (checkout.session.completed)
    // We only show the key on screen here to avoid duplicate emails

    // Create session
    const token = await createSessionToken({
      email,
      tier,
      licenseId: sessionId,
      expiresAt: expDate,
    });

    const res = NextResponse.json({
      success: true,
      email,
      licenseKey,
      tier,
      expDate,
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
