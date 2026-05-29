import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { jwtVerify } from "jose";

const SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || "keyblind-dashboard-dev-secret-change-in-production"
);

const PUBLIC_PATHS = ["/login", "/activate", "/connect"];

export async function middleware(req: NextRequest) {
  const token = req.cookies.get("keyblind_token")?.value;
  const pathname = req.nextUrl.pathname;
  const isPublic = PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith("/api/auth/"));

  if (!token && !isPublic) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  if (token && pathname === "/login") {
    try {
      await jwtVerify(token, SECRET);
      return NextResponse.redirect(new URL("/", req.url));
    } catch {
      // Invalid token, stay on login
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next|api|favicon.ico).*)"],
};
