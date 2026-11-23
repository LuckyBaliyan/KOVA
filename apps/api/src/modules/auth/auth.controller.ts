import { CookieOptions, NextFunction, Request, Response } from "express";
import { Role } from "@prisma/client";
import { RegisterUserSchema } from "@kova/shared"; // packages/shared ke package.json name ke hisaab se adjust kar lena
import { AppError } from "../../utils/AppError";
import {
      refreshSession,
      registerUser,
} from "./auth.service";

/**
 * @description Store and retrieve auth cookies and manage sessions and type checks using shared schema.
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

function setAuthCookies(
      res: Response,
      accessToken: string,
      refreshToken: string
) {
      res.cookie("accessToken", accessToken, accessCookieOptions);
      res.cookie("refreshToken", refreshToken, refreshCookieOptions);
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

            const { fullName, email, password } = parsed.data;
            const role = req.body?.role as Role | undefined;

            const { user, accessToken, refreshToken } = await registerUser({
                  email,
                  password,
                  name: fullName,
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