import { NextFunction, Request, Response } from "express";
import { jwtPayload, verifyAcessToken } from "../utils/jwt";
import { AppError } from "../utils/AppError";


/**
 * @description middleware to authenticate weather a user is logged 
 * in or not 
 */


//tells Express that request object have an additional type user
declare global {
      namespace Express {
            interface Request {
                  user?: jwtPayload // --> user : {userId, role}
            }
      }
}

export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
      try {

            const token = typeof req.cookies?.accessToken === "string" ?
                  req.cookies.accessToken
                  : undefined;

            if (!token) {
                  return next(new AppError("Authentication required!", 401));
            }

            const decoded = verifyAcessToken(token);
            req.user = decoded;
            return next();

      } catch (error) {
            return next(new AppError(
                  "Invalid or expired acess token",
                  401
            ));
      }
}