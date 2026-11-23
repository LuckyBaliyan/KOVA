import { NextFunction, Response, Request } from "express";
import { AppError } from "../utils/AppError";

export function requireRole(...allowedRoles: string[]) {
      return (req: Request, _res: Response, next: NextFunction): void => {
            if (!req.user) {
                  return next(new AppError("Authentication required", 401));
            }

            if (!allowedRoles.includes(req.user.role)) {
                  return next(new AppError(
                        "Forbidden: not Authorized for this action",
                        403
                  ));
            }

            return next();
      }
}