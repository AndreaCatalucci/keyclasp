import crypto from "node:crypto";

interface LicensePayload {
  tier: "free" | "pro" | "team";
  email: string;
  exp: string;
  iat: string;
  id: string;
}

export function generateLicenseKey(tier: string, email: string, expDate: string): string {
  const privKeyBase64 = process.env.KEYBLIND_SIGNING_KEY;
  if (!privKeyBase64) throw new Error("KEYBLIND_SIGNING_KEY not set");

  const today = new Date().toISOString().slice(0, 10);
  const id = `lic_${crypto.randomBytes(8).toString("hex")}`;

  const payload: LicensePayload = {
    tier: tier as LicensePayload["tier"],
    email,
    exp: expDate,
    iat: today,
    id,
  };

  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privKeyBase64, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const data = Buffer.from(JSON.stringify(payload));
  const signature = crypto.sign(null, data, privateKey);

  return `keyblind.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${signature.toString("base64url")}`;
}
