import { NextFunction, Request, Response } from "express";
import { AppError } from "../utils/AppError";


/**
 * @description send the altered or normal app erros via api and its a global
 * 4 parameter error used directly by express
 * @returns api response to send error to frontend
 */

export function errorHandler(
      err: unknown,
      _req: Request,
      res: Response,
      _next: NextFunction
): Response {
      if (err instanceof AppError) {
            return res.status(err.statusCode).json({
                  success: false,
                  message: err.message,
            });
      }

      if (err instanceof SyntaxError && "status" in err && err.status === 400) {
            return res.status(400).json({
                  success: false,
                  message: "Invalid JSON payload",
            });
      }

      console.error("Unhandled Error:", err);

      return res.status(500).json({
            success: false,
            message: "Internal server error",
      });
}