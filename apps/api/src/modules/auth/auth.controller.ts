import { CookieOptions, NextFunction, Request, Response } from "express";
import { Role } from "@prisma/client";
import { LoginSchema, RegisterUserSchema } from "@kova/shared"; // packages/shared ke package.json name ke hisaab se adjust kar lena
import { AppError } from "../../utils/AppError";
import {
      refreshSession,
      registerUser,
      loginUser,
      logOutUser,
      getCurrentUser,
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

//set cookies when register or logging in
function setAuthCookies(
      res: Response,
      accessToken: string,
      refreshToken: string
) {
      res.cookie("accessToken", accessToken, accessCookieOptions);
      res.cookie("refreshToken", refreshToken, refreshCookieOptions);
}

//clear the cookies when logout
function clearAuthCookies(res: Response) {
      res.clearCookie("accessToken", {
            httpOnly: true,
            sameSite: isProd ? "none" : "lax",
            secure: isProd,
            path: "/",
      });

      res.clearCookie("refreshToken", {
            httpOnly: true,
            sameSite: isProd ? "none" : "lax",
            secure: isProd,
            path: "/api/auth",
      });
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

/**
 * @param req user loign dets like email and password
 * @param res send logged in user 
 * @param next pass the further action to next function 
 * @description used to send logged in user response by passing params to services
 */
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
                  password
            });

            setAuthCookies(res, accessToken, refreshToken);
            res.status(200).json({ success: true, data: { user } });

      } catch (error) {
            next(error);
      }
}


export async function logOut(
      req: Request,
      res: Response,
      next: NextFunction
) {

      try {
            const refreshToken = typeof req.cookies?.refreshToken === "string"
                  ? req.cookies.refreshToken : undefined;

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