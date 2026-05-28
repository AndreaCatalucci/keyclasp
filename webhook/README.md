# Keyblind Stripe Webhook

Handles Stripe checkout completion → generates a signed license key → emails it to the customer.

## Setup

1. Install dependencies:
```bash
cd webhook
npm install
```

2. Set environment variables in Vercel dashboard (or `.env` for local):
   - `STRIPE_SECRET_KEY` — from Stripe Dashboard → API keys
   - `STRIPE_WEBHOOK_SECRET` — from Stripe Dashboard → Webhooks → add endpoint → copy signing secret
   - `KEYBLIND_SIGNING_KEY` — your Ed25519 private key (keep secret!)
   - `RESEND_API_KEY` — from resend.com (free tier: 100 emails/day)

3. Generate your signing keypair:
```bash
cd ..
npx tsx scripts/generate-license.ts --gen-keypair
# Copy KEYBLIND_SIGNING_KEY to Vercel env vars
# Copy KEYBLIND_PUBLIC_KEY to the Keyblind build (src/license.ts DEFAULT_KEY)
```

4. Deploy:
```bash
vercel deploy --prod
```

5. Configure Stripe webhook:
   - Stripe Dashboard → Webhooks → Add endpoint
   - URL: `https://your-deploy.vercel.app/api/webhook`
   - Events: `checkout.session.completed`

6. Create a Stripe Payment Link or Checkout session with metadata:
   - `tier`: `pro` or `team`
   - `expiry_years`: `1` (default)
