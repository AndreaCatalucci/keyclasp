import crypto from "node:crypto";
import http from "node:http";
import { execSync } from "node:child_process";
import { storeSecret, resolveSecret, deleteSecret } from "./vault.js";

const SSO_PREFIX = "_keyblind_sso";
const CONFIG_KEY = `${SSO_PREFIX}:config`;
const TOKEN_KEY = `${SSO_PREFIX}:token`;

export interface SSOConfig {
  provider: "google" | "okta" | "azure" | "oidc";
  clientId: string;
  domain?: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  scopes: string[];
}

export interface SSOToken {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresAt: number;
  claims: IDTokenClaims;
}

export interface IDTokenClaims {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
  hd?: string;
  [key: string]: unknown;
}

const PROVIDER_PRESETS: Record<string, (c: { clientId: string; domain?: string }) => SSOConfig> = {
  google: (c) => ({
    provider: "google",
    clientId: c.clientId,
    domain: c.domain,
    issuer: "https://accounts.google.com",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
    scopes: ["openid", "email", "profile"],
  }),
  okta: (c) => ({
    provider: "okta",
    clientId: c.clientId,
    domain: c.domain,
    issuer: `https://${c.domain}/oauth2/default`,
    authorizationEndpoint: `https://${c.domain}/oauth2/default/v1/authorize`,
    tokenEndpoint: `https://${c.domain}/oauth2/default/v1/token`,
    jwksUri: `https://${c.domain}/oauth2/default/v1/keys`,
    scopes: ["openid", "email", "profile"],
  }),
  azure: (c) => ({
    provider: "azure",
    clientId: c.clientId,
    domain: c.domain,
    issuer: `https://login.microsoftonline.com/${c.domain}/v2.0`,
    authorizationEndpoint: `https://login.microsoftonline.com/${c.domain}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${c.domain}/oauth2/v2.0/token`,
    jwksUri: `https://login.microsoftonline.com/${c.domain}/discovery/v2.0/keys`,
    scopes: ["openid", "email", "profile"],
  }),
};

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function sha256(data: string): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

function generateCodeVerifier(): string {
  return base64url(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier: string): string {
  return base64url(sha256(verifier));
}

function decodeJWT(token: string): { header: any; payload: any; signature: string } {
  const [headerB64, payloadB64, signature] = token.split(".");
  return {
    header: JSON.parse(Buffer.from(headerB64, "base64url").toString()),
    payload: JSON.parse(Buffer.from(payloadB64, "base64url").toString()),
    signature,
  };
}

async function fetchJWKS(jwksUri: string): Promise<any> {
  const res = await fetch(jwksUri);
  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`);
  return res.json();
}

async function validateIDToken(idToken: string, config: SSOConfig, nonce?: string): Promise<IDTokenClaims> {
  const { header, payload: claims } = decodeJWT(idToken);

  // Validate claims
  if (claims.iss !== config.issuer) throw new Error(`Invalid issuer: ${claims.iss}`);
  if (claims.aud !== config.clientId) throw new Error(`Invalid audience: ${claims.aud}`);
  if (claims.exp && claims.exp * 1000 < Date.now()) throw new Error("ID token has expired");
  if (nonce && claims.nonce !== nonce) throw new Error("Nonce mismatch");

  // Fetch JWKS and verify signature
  const jwks = await fetchJWKS(config.jwksUri);
  const keyData = jwks.keys?.find((k: any) => k.kid === header.kid);
  if (!keyData) throw new Error(`No JWK found for kid: ${header.kid}`);

  // Reconstruct PEM from JWK (RSA)
  const jwk = crypto.createPublicKey({ key: keyData, format: "jwk" });
  const [headerB64, payloadB64] = idToken.split(".");
  const signedData = `${headerB64}.${payloadB64}`;
  const signature = Buffer.from(claims.signature || idToken.split(".")[2], "base64url");

  const valid = crypto.verify(
    "SHA256",
    Buffer.from(signedData),
    jwk,
    signature
  );
  if (!valid) throw new Error("ID token signature verification failed");

  return {
    sub: claims.sub,
    email: claims.email,
    email_verified: Boolean(claims.email_verified),
    name: claims.name,
    picture: claims.picture,
    hd: claims.hd || undefined,
    ...claims,
  };
}

export async function configureSSO(config: { provider: string; clientId: string; domain?: string }): Promise<void> {
  const preset = PROVIDER_PRESETS[config.provider];
  if (!preset) throw new Error(`Unknown provider: ${config.provider}. Supported: google, okta, azure`);
  const fullConfig = preset({ clientId: config.clientId, domain: config.domain });
  storeSecret(CONFIG_KEY, JSON.stringify(fullConfig));
}

export function getSSOConfig(): SSOConfig | null {
  const raw = resolveSecret(CONFIG_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

export async function ssoLogin(timeoutMs: number = 120000): Promise<SSOToken> {
  const config = getSSOConfig();
  if (!config) throw new Error("SSO not configured. Run: keyblind sso configure");

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const nonce = base64url(crypto.randomBytes(16));
  const state = base64url(crypto.randomBytes(16));
  const redirectUri = "http://localhost:3101/callback";

  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.set("client_id", config.clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", config.scopes.join(" "));
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("nonce", nonce);
  authUrl.searchParams.set("state", state);

  // Start callback server
  const authCode = await new Promise<string>((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url || "/", `http://localhost:3101`);
      if (url.pathname === "/callback") {
        const returnedState = url.searchParams.get("state");
        const code = url.searchParams.get("code");
        const error = url.searchParams.get("error");

        if (error) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(`<h1>Authentication failed</h1><p>${error}</p>`);
          server.close();
          reject(new Error(error));
          return;
        }

        if (returnedState !== state) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end("<h1>Invalid state</h1>");
          server.close();
          reject(new Error("State mismatch"));
          return;
        }

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end("<h1>Authentication successful!</h1><p>You may close this window.</p>");
        server.close();

        if (code) resolve(code);
        else reject(new Error("No authorization code received"));
      }
    });

    const timeout = setTimeout(() => {
      server.close();
      reject(new Error(`SSO login timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    server.listen(3101, () => {
      const platform = process.platform;
      const openCmd = platform === "darwin" ? "open" : platform === "linux" ? "xdg-open" : "start";
      try {
        execSync(`${openCmd} "${authUrl.toString()}"`);
      } catch {
        console.error(`Please open this URL in your browser:\n${authUrl.toString()}`);
      }
      console.log("Waiting for authentication in browser...");
    });

    server.on("close", () => clearTimeout(timeout));
  });

  // Exchange code for tokens
  const tokenRes = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: redirectUri,
      client_id: config.clientId,
      code_verifier: codeVerifier,
    }).toString(),
  });

  if (!tokenRes.ok) {
    const errText = await tokenRes.text();
    throw new Error(`Token exchange failed: ${errText}`);
  }

  const tokenData: any = await tokenRes.json();
  const claims = await validateIDToken(tokenData.id_token, config, nonce);

  const token: SSOToken = {
    accessToken: tokenData.access_token,
    idToken: tokenData.id_token,
    refreshToken: tokenData.refresh_token,
    expiresAt: Math.floor(Date.now() / 1000) + (tokenData.expires_in || 3600),
    claims,
  };

  storeSecret(TOKEN_KEY, JSON.stringify(token));
  return token;
}

export function getSSOToken(): SSOToken | null {
  const raw = resolveSecret(TOKEN_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

export function isSSOAuthenticated(): boolean {
  const token = getSSOToken();
  return token !== null && token.expiresAt * 1000 > Date.now();
}

export async function refreshSSOToken(): Promise<SSOToken | null> {
  const config = getSSOConfig();
  const token = getSSOToken();
  if (!config || !token || !token.refreshToken) return null;

  const res = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: token.refreshToken,
      client_id: config.clientId,
    }).toString(),
  });

  if (!res.ok) {
    ssoLogout();
    return null;
  }

  const tokenData: any = await res.json();
  const newToken: SSOToken = {
    accessToken: tokenData.access_token,
    idToken: tokenData.id_token || token.idToken,
    refreshToken: tokenData.refresh_token || token.refreshToken,
    expiresAt: Math.floor(Date.now() / 1000) + (tokenData.expires_in || 3600),
    claims: token.claims,
  };

  storeSecret(TOKEN_KEY, JSON.stringify(newToken));
  return newToken;
}

export function ssoLogout(): void {
  deleteSecret(TOKEN_KEY);
}
