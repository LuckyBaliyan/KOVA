import { CookieOptions, NextFunction, Request, Response } from "express";
import { Role } from "@prisma/client";
import { AppError } from "../../utils/AppError";
import {
      refreshSession,
      registerUser,
} from "./auth.service";

/**
 * @description buisness logic store and retirive cookies and manage sessions.
 */

const isProd = process.env.NODE_ENV === "production";

const accessCookieOptions: CookieOptions = {
      httpOnly: true,
      sameSite: isProd ? "none" : "lax",
      secure: isProd,
      maxAge: 15 * 60 * 1000,
      path: "/",
};

const refreshCookieOptions: CookieOptions = {
      httpOnly: true,
      sameSite: isProd ? "none" : "lax",
      secure: isProd,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth",
};

function setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
      res.cookie("accessToken", accessToken, accessCookieOptions);
      res.cookie("refreshToken", refreshToken, refreshCookieOptions);
}


export async function register(
      req: Request,
      res: Response,
      next: NextFunction
): Promise<void> {
      try {
            const { email, password, name, role } = req.body as {
                  email?: string;
                  password?: string;
                  name?: string;
                  role?: Role;
            };

            if (!email || !password) {
                  return next(new AppError("Email and password are required", 400));
            }

            if (password.length < 8) {
                  return next(
                        new AppError("Password must be at least 8 characters long", 400)
                  );
            }

            const { user, accessToken, refreshToken } = await registerUser({
                  email,
                  password,
                  name,
                  role,
            });

            setAuthCookies(res, accessToken, refreshToken);
            res.status(201).json({ success: true, data: { user } });
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
