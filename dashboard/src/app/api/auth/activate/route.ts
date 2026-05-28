import { NextResponse } from "next/server";
import { createSessionToken } from "@/lib/auth";
import { generateLicenseKey } from "@/lib/license-gen";

async function sendLicenseEmail(email: string, licenseKey: string, tier: string, expDate: string): Promise<void> {
  const resendApiKey = process.env.RESEND_API_KEY;
  if (!resendApiKey) {
    console.log("RESEND_API_KEY not set — license key:", licenseKey);
    return;
  }

  const tierLabel = tier === "team" ? "Team" : "Pro";
  const activationCmd = `keyblind activate ${licenseKey}`;

  const { Resend } = await import("resend");
  const resend = new Resend(resendApiKey);

  await resend.emails.send({
    from: "Keyblind <license@keyblind.dev>",
    to: email,
    subject: `Your Keyblind ${tierLabel} License`,
    html: [
      `<h1>Keyblind ${tierLabel} — License Key</h1>`,
      `<p>Thanks for upgrading to Keyblind ${tierLabel}!</p>`,
      `<p><strong>Your license key:</strong></p>`,
      `<pre style="background:#1a1b26;color:#a6e3a1;padding:16px;border-radius:8px;font-size:13px;word-break:break-all;white-space:pre-wrap">${licenseKey}</pre>`,
      `<p><strong>Activate it:</strong></p>`,
      `<pre style="background:#1a1b26;color:#cdd6f4;padding:16px;border-radius:8px">${activationCmd}</pre>`,
      `<p>Your license is valid until <strong>${expDate}</strong>.</p>`,
      `<p><a href="https://app.keyblind.dev/login">Sign into the dashboard</a> with your license key.</p>`,
      `<hr>`,
      `<small>Keyblind — Blind AI to Your Keys. Zero network. Zero telemetry.</small>`,
    ].join("\n"),
  });
}

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

    // Send email (non-blocking — don't fail if email delivery fails)
    sendLicenseEmail(email, licenseKey, tier, expDate).catch((err) =>
      console.error("Email delivery failed:", err.message)
    );

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
