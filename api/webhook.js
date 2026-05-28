/**
 * Stripe Webhook — Keyblind License Delivery
 * Endpoint: https://keyblind.vercel.app/api/webhook
 */

import crypto from "node:crypto";

function generateLicenseKey(tier, email, expDate) {
  const privKeyBase64 = process.env.KEYBLIND_SIGNING_KEY;
  if (!privKeyBase64) throw new Error("KEYBLIND_SIGNING_KEY not set");

  const today = new Date().toISOString().slice(0, 10);
  const id = `lic_${crypto.randomBytes(8).toString("hex")}`;

  const payload = { tier, email, exp: expDate, iat: today, id };
  const data = Buffer.from(JSON.stringify(payload));

  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privKeyBase64, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const signature = crypto.sign(null, data, privateKey);
  return `keyblind.${data.toString("base64url")}.${signature.toString("base64url")}`;
}

async function sendLicenseEmail(email, licenseKey, tier, expDate) {
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
      `<p>Questions? Reply to this email or open an issue on <a href="https://github.com/aarifmms/keyblind">GitHub</a>.</p>`,
      `<hr><small>Keyblind — Blind AI to Your Keys. Zero network. Zero telemetry.</small>`,
    ].join("\n"),
  });
}

export async function POST(req) {
  const sig = req.headers.get("stripe-signature");
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!sig || !webhookSecret) {
    return Response.json({ error: "Missing signature" }, { status: 400 });
  }

  const body = await req.text();

  let event;
  try {
    const { default: Stripe } = await import("stripe");
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    event = stripe.webhooks.constructEvent(body, sig, webhookSecret);
  } catch (err) {
    console.error("Webhook signature verification failed:", err.message);
    return Response.json({ error: "Signature verification failed" }, { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const customerEmail = session.customer_details?.email || session.customer_email;
    const tier = session.metadata?.tier || "pro";
    const expYears = parseInt(session.metadata?.expiry_years || "1", 10);

    if (!customerEmail) {
      console.error("No customer email:", session.id);
      return Response.json({ error: "No customer email" }, { status: 400 });
    }

    const expDate = new Date(Date.now() + expYears * 365 * 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);

    try {
      const licenseKey = generateLicenseKey(tier, customerEmail, expDate);
      await sendLicenseEmail(customerEmail, licenseKey, tier, expDate);
      console.log(`License delivered: ${tier} → ${customerEmail} (expires ${expDate})`);
      return Response.json({ success: true, message: `License key sent to ${customerEmail}` });
    } catch (err) {
      console.error("License generation failed:", err.message);
      return Response.json({ error: "License generation failed" }, { status: 500 });
    }
  }

  return Response.json({ received: true });
}

export async function GET() {
  return Response.json({ status: "ok", endpoint: "Keyblind Stripe Webhook" });
}
