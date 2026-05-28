#!/usr/bin/env npx tsx
/**
 * Generate signed Keyblind license keys.
 *
 * Usage:
 *   KEYBLIND_SIGNING_KEY=<private-key-base64> npx tsx scripts/generate-license.ts --tier pro --email user@example.com [--exp 2027-05-27]
 *
 * Generate a keypair first:
 *   npx tsx scripts/generate-license.ts --gen-keypair
 */

import crypto from "node:crypto";

interface LicensePayload {
  tier: "free" | "pro" | "team";
  email: string;
  exp: string;
  iat: string;
  id: string;
}

function generateKeypair(): void {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  const pubBase64 = publicKey.toString("base64");
  const privBase64 = privateKey.toString("base64");

  console.log("Add this to your Keyblind build environment:");
  console.log(`  KEYBLIND_PUBLIC_KEY=${pubBase64}`);
  console.log("");
  console.log("Keep this secret — use it to sign license keys:");
  console.log(`  KEYBLIND_SIGNING_KEY=${privBase64}`);
  console.log("");
  console.log("Public key hex:", publicKey.toString("hex"));
  console.log("Private key hex:", privateKey.toString("hex"));
}

function signLicense(tier: string, email: string, expDate: string): void {
  const privKeyBase64 = process.env.KEYBLIND_SIGNING_KEY;
  if (!privKeyBase64) {
    console.error("KEYBLIND_SIGNING_KEY environment variable is required.");
    console.error("Run with --gen-keypair to generate keys first.");
    process.exit(1);
  }

  if (!["free", "pro", "team"].includes(tier)) {
    console.error("Tier must be: free, pro, or team");
    process.exit(1);
  }

  const today = new Date().toISOString().slice(0, 10);
  const id = `lic_${crypto.randomBytes(8).toString("hex")}`;

  const payload: LicensePayload = {
    tier: tier as LicensePayload["tier"],
    email,
    exp: expDate || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
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

  const key = `keyblind.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${signature.toString("base64url")}`;

  console.log("");
  console.log(`License key (${tier} tier, expires ${payload.exp}):`);
  console.log("");
  console.log(key);
  console.log("");
  console.log(`Share this with the user. They run: keyblind activate ${key.slice(0, 30)}...`);
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.includes("--gen-keypair")) {
    generateKeypair();
    return;
  }

  const tierIdx = args.indexOf("--tier");
  const emailIdx = args.indexOf("--email");
  const expIdx = args.indexOf("--exp");

  if (tierIdx === -1 || emailIdx === -1) {
    console.error("Usage: npx tsx scripts/generate-license.ts --tier <pro|team> --email <email> [--exp YYYY-MM-DD]");
    console.error("       npx tsx scripts/generate-license.ts --gen-keypair");
    process.exit(1);
  }

  const tier = args[tierIdx + 1];
  const email = args[emailIdx + 1];
  const exp = expIdx !== -1 ? args[expIdx + 1] : "";

  signLicense(tier, email, exp);
}

main();
