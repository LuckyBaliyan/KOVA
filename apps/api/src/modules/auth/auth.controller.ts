import crypto from "crypto";
import { CookieOptions, NextFunction, Request, Response } from "express";
import { Role } from "@prisma/client";
import { LoginSchema, RegisterUserSchema } from "@kova/shared";
import { AppError } from "../../utils/AppError";
import {
      refreshSession,
      registerUser,
      loginUser,
      logOutUser,
      getCurrentUser,
      googleAuthUser,
} from "./auth.service";

import { env } from "../../config/env";

const accessCookieOptions: CookieOptions = {
      httpOnly: true,
      sameSite: env.isProd ? "none" : "lax",
      secure: env.isProd,
      maxAge: 15 * 60 * 1000,
      path: "/",
};

const refreshCookieOptions: CookieOptions = {
      httpOnly: true,
      sameSite: env.isProd ? "none" : "lax",
      secure: env.isProd,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth",
};

const oauthStateCookieOptions: CookieOptions = {
      httpOnly: true,
      sameSite: env.isProd ? "none" : "lax",
      secure: env.isProd,
      maxAge: 10 * 60 * 1000,
      path: "/api/auth/google",
};

function setAuthCookies(
      res: Response,
      accessToken: string,
      refreshToken: string
) {
      res.cookie("accessToken", accessToken, accessCookieOptions);
      res.cookie("refreshToken", refreshToken, refreshCookieOptions);
}

function clearAuthCookies(res: Response) {
      res.clearCookie("accessToken", {
            httpOnly: true,
            sameSite: env.isProd ? "none" : "lax",
            secure: env.isProd,
            path: "/",
      });

      res.clearCookie("refreshToken", {
            httpOnly: true,
            sameSite: env.isProd ? "none" : "lax",
            secure: env.isProd,
            path: "/api/auth",
      });
}

function getPostAuthRedirectPath(role: Role): string {
      return role === Role.SELLER ? "/seller/dashboard" : "/";
}

function parseStateRole(stateParam: unknown): Role {
      if (typeof stateParam !== "string" || !stateParam) {
            return Role.BUYER;
      }

      try {
            const decoded = JSON.parse(
                  Buffer.from(stateParam, "base64url").toString("utf8")
            ) as { role?: unknown };
            return decoded.role === Role.SELLER ? Role.SELLER : Role.BUYER;
      } catch {
            return Role.BUYER;
      }
}

export async function register(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            const parsed = RegisterUserSchema.safeParse(req.body);
            if (!parsed.success) {
                  const message = parsed.error.issues[0]?.message || "Invalid input";
                  return next(new AppError(message, 400));
            }

            const { name, email, password, phone, role, googleId, avatarUrl } =
                  parsed.data;

            if (!googleId && !password) {
                  return next(new AppError("Password is required", 400));
            }

            const { user, accessToken, refreshToken } = await registerUser({
                  email,
                  password,
                  name: name,
                  phone: phone || undefined,
                  role,
                  googleId,
                  avatarUrl,
            });

            setAuthCookies(res, accessToken, refreshToken);
            res.status(201).json({ success: true, data: { user } });
      } catch (err) {
            next(err);
      }
}

export async function login(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            const parsed = LoginSchema.safeParse(req.body);
            if (!parsed.success) {
                  const message = parsed.error.issues[0]?.message || "Invalid input";
                  return next(new AppError(message, 400));
            }

            const { email, password } = parsed.data;
            const { user, accessToken, refreshToken } = await loginUser({
                  email,
                  password,
            });

            setAuthCookies(res, accessToken, refreshToken);
            res.status(200).json({ success: true, data: { user } });
      } catch (error) {
            next(error);
      }
}

export async function googleStart(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            if (!env.GOOGLE_CLIENT_ID) {
                  return next(new AppError("Google OAuth is not configured", 500));
            }

            const requestedRole: Role =
                  req.query.role === Role.SELLER ? Role.SELLER : Role.BUYER;
            const nonce = crypto.randomBytes(16).toString("hex");
            const statePayload = Buffer.from(
                  JSON.stringify({ role: requestedRole, nonce })
            ).toString("base64url");

            res.cookie("google_oauth_state", statePayload, oauthStateCookieOptions);

            const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
            authUrl.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
            authUrl.searchParams.set("redirect_uri", env.GOOGLE_CALLBACK_URL);
            authUrl.searchParams.set("response_type", "code");
            authUrl.searchParams.set("scope", "openid email profile");
            authUrl.searchParams.set("state", statePayload);
            authUrl.searchParams.set("prompt", "select_account");

            res.redirect(authUrl.toString());
      } catch (error) {
            next(error);
      }
}

export async function googleCallback(
      req: Request,
      res: Response
): Promise<void> {
      try {
            const { code, state, error } = req.query;
            const savedState =
                  typeof req.cookies?.google_oauth_state === "string"
                        ? req.cookies.google_oauth_state
                        : undefined;

            res.clearCookie("google_oauth_state", {
                  httpOnly: true,
                  sameSite: env.isProd ? "none" : "lax",
                  secure: env.isProd,
                  path: "/api/auth/google",
            });

            if (error || typeof code !== "string" || !code) {
                  res.redirect(`${env.FRONTEND_URL}/login?error=google_auth_cancelled`);
                  return;
            }

            if (savedState && typeof state === "string" && savedState !== state) {
                  res.redirect(`${env.FRONTEND_URL}/login?error=invalid_oauth_state`);
                  return;
            }

            const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded" },
                  body: new URLSearchParams({
                        code,
                        client_id: env.GOOGLE_CLIENT_ID,
                        client_secret: env.GOOGLE_CLIENT_SECRET,
                        redirect_uri: env.GOOGLE_CALLBACK_URL,
                        grant_type: "authorization_code",
                  }),
            });

            if (!tokenRes.ok) {
                  res.redirect(`${env.FRONTEND_URL}/login?error=google_token_failed`);
                  return;
            }

            const tokenData = (await tokenRes.json()) as {
                  access_token?: string;
            };

            if (!tokenData.access_token) {
                  res.redirect(`${env.FRONTEND_URL}/login?error=google_token_missing`);
                  return;
            }

            const profileRes = await fetch(
                  "https://www.googleapis.com/oauth2/v2/userinfo",
                  {
                        headers: {
                              Authorization: `Bearer ${tokenData.access_token}`,
                        },
                  }
            );

            if (!profileRes.ok) {
                  res.redirect(`${env.FRONTEND_URL}/login?error=google_profile_failed`);
                  return;
            }

            const profile = (await profileRes.json()) as {
                  id?: string;
                  email?: string;
                  verified_email?: boolean;
                  name?: string;
                  picture?: string;
            };

            if (!profile.id || !profile.email || profile.verified_email === false) {
                  res.redirect(`${env.FRONTEND_URL}/login?error=google_email_unverified`);
                  return;
            }

            const requestedRole = parseStateRole(state);

            const { user, accessToken, refreshToken } = await googleAuthUser({
                  googleId: profile.id,
                  email: profile.email,
                  name: profile.name ?? null,
                  avatarUrl: profile.picture ?? null,
                  requestedRole,
            });

            setAuthCookies(res, accessToken, refreshToken);
            res.redirect(`${env.FRONTEND_URL}${getPostAuthRedirectPath(user.role)}`);
      } catch {
            res.redirect(`${env.FRONTEND_URL}/login?error=google_auth_error`);
      }
}

export async function logOut(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            const refreshToken =
                  typeof req.cookies?.refreshToken === "string"
                        ? req.cookies.refreshToken
                        : undefined;

            await logOutUser(refreshToken);
            clearAuthCookies(res);

            res.status(200).json({
                  success: true,
                  message: "Logged out successfully",
            });
      } catch (error) {
            next(error);
      }
}

export async function getMe(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            const userId = req.user?.userId;

            if (!userId) {
                  return next(new AppError("Authentication required!", 401));
            }

            const user = await getCurrentUser(userId);

            res.status(200).json({
                  success: true,
                  data: { user },
            });
      } catch (err) {
            next(err);
      }
}

export async function refresh(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            const token =
                  typeof req.cookies?.refreshToken === "string"
                        ? req.cookies.refreshToken
                        : undefined;

            const { accessToken, refreshToken } = await refreshSession(token);
            setAuthCookies(res, accessToken, refreshToken);

            res.status(200).json({ success: true, message: "Session refreshed" });
      } catch (err) {
            next(err);
      }
}