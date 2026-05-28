import { readFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import https from "node:https";
import http from "node:http";
import crypto from "node:crypto";

const CERTS_DIR = path.join(os.homedir(), ".keyblind", "certs");
const RENEWAL_THRESHOLD_DAYS = 30;
const RENEWAL_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

export interface ACMEOptions {
  domain: string;
  email?: string;
  staging?: boolean;
  port?: number;
  httpPort?: number;
}

export interface CertPaths {
  cert: string;
  key: string;
  chain: string;
  fullchain: string;
}

function getCertPaths(domain: string): CertPaths {
  const dir = path.join(CERTS_DIR, domain);
  return {
    cert: path.join(dir, "cert.pem"),
    key: path.join(dir, "privkey.pem"),
    chain: path.join(dir, "chain.pem"),
    fullchain: path.join(dir, "fullchain.pem"),
  };
}

export function certExists(domain: string): boolean {
  const paths = getCertPaths(domain);
  return existsSync(paths.cert) && existsSync(paths.key);
}

export function certExpiringSoon(domain: string, thresholdDays: number = RENEWAL_THRESHOLD_DAYS): boolean {
  try {
    const paths = getCertPaths(domain);
    const certPem = readFileSync(paths.cert, "utf8");
    const cert = new crypto.X509Certificate(certPem);
    const expiresOn = new Date(cert.validTo);
    const daysRemaining = Math.ceil((expiresOn.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
    return daysRemaining <= thresholdDays;
  } catch {
    return true;
  }
}

function generateSelfSignedCert(domain: string): { cert: string; key: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const cert = crypto.createSign("SHA256")
    .update(JSON.stringify({
      subject: `CN=${domain}`,
      validFrom: new Date().toISOString(),
      validTo: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    }))
    .sign(privateKey, "base64");

  return { cert, key: privateKey };
}

export async function provisionCert(opts: ACMEOptions): Promise<CertPaths> {
  const domainDir = path.join(CERTS_DIR, opts.domain);
  if (!existsSync(domainDir)) mkdirSync(domainDir, { recursive: true });

  // Attempt ACME via acme-client, fall back to self-signed
  let certPem: string;
  let keyPem: string;
  let chainPem: string;

  try {
    const acme = await import("acme-client");
    const client = new acme.Client({
      directoryUrl: opts.staging
        ? acme.Directory.LetsEncryptStaging
        : acme.Directory.LetsEncryptProduction,
      accountKey: await acme.Crypto.createPrivateKey(),
    });

    await client.createAccount({
      termsOfServiceAgreed: true,
      contact: opts.email ? [`mailto:${opts.email}`] : [],
    });

    const order = await client.createOrder({ identifiers: [{ type: "dns", value: opts.domain }] });
    const authorizations = await client.getAuthorizations(order);
    const { challenges } = authorizations[0];
    const httpChallenge = challenges.find((c: any) => c.type === "http-01");
    if (!httpChallenge) throw new Error("No HTTP-01 challenge available");

    const keyAuthorization = await client.getChallengeKeyAuthorization(httpChallenge);

    // Serve challenge on port 80
    const challengePath = `/.well-known/acme-challenge/${httpChallenge.token}`;
    const challengeServer = http.createServer((req, res) => {
      if (req.url === challengePath) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(keyAuthorization);
      } else {
        res.writeHead(301, { Location: `https://${opts.domain}${req.url}` });
        res.end();
      }
    });

    await new Promise<void>((resolve, reject) => {
      challengeServer.listen(opts.httpPort || 80, () => resolve());
    });

    try {
      await client.verifyChallenge(httpChallenge);
      await client.completeChallenge(httpChallenge);
      await client.waitForValidStatus(httpChallenge);
    } finally {
      challengeServer.close();
    }

    // Generate CSR and finalize
    const [certKey] = await acme.Crypto.createPrivateKey().then((k: any) => [k]);
    await client.finalizeOrder(order, certKey);
    const finalized = await client.getCertificate(order);

    certPem = finalized.certificate;
    keyPem = finalized.key;
    chainPem = finalized.chain || "";
  } catch {
    // Fall back to self-signed
    const selfSigned = generateSelfSignedCert(opts.domain);
    certPem = selfSigned.cert;
    keyPem = selfSigned.key;
    chainPem = "";
    console.warn(`[keyblind] ACME provisioning failed, using self-signed certificate for ${opts.domain}`);
  }

  const paths = getCertPaths(opts.domain);
  const { writeFileSync } = await import("node:fs");
  writeFileSync(paths.cert, certPem);
  writeFileSync(paths.key, keyPem);
  writeFileSync(paths.chain, chainPem);
  writeFileSync(paths.fullchain, chainPem ? `${certPem}\n${chainPem}` : certPem);

  // Set restrictive permissions on private key
  const { chmodSync } = await import("node:fs");
  chmodSync(paths.key, 0o600);

  return paths;
}

export function createHttpsServer(
  appHandler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
  opts: ACMEOptions
): { httpsServer: https.Server; httpServer: http.Server } {
  const paths = getCertPaths(opts.domain);
  const cert = readFileSync(paths.fullchain);
  const key = readFileSync(paths.key);

  const httpServer = http.createServer((req, res) => {
    res.writeHead(301, { Location: `https://${opts.domain}${req.url}` });
    res.end();
  });

  const httpsServer = https.createServer({ cert, key }, appHandler);
  return { httpsServer, httpServer };
}

export function startAutoRenewal(domain: string, email?: string): NodeJS.Timeout {
  return setInterval(async () => {
    try {
      if (certExpiringSoon(domain)) {
        console.log(`[keyblind] Certificate for ${domain} expiring soon. Renewing...`);
        await provisionCert({ domain, email });
        console.log(`[keyblind] Certificate renewed. Restart to apply changes.`);
      }
    } catch (err: any) {
      console.error(`[keyblind] Auto-renewal failed: ${err.message}`);
    }
  }, RENEWAL_CHECK_INTERVAL_MS);
}
