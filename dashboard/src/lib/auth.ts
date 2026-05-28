import * as jose from "jose";

const SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || "keyblind-dashboard-dev-secret-change-in-production"
);

export interface SessionUser {
  email: string;
  tier: string;
  licenseKey: string;
}

export async function createSessionToken(user: SessionUser): Promise<string> {
  return new jose.SignJWT({ ...user })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(SECRET);
}

export async function verifySessionToken(token: string): Promise<SessionUser | null> {
  try {
    const { payload } = await jose.jwtVerify(token, SECRET);
    return payload as unknown as SessionUser;
  } catch {
    return null;
  }
}
