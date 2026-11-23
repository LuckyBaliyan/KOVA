import jwt, { SignOptions } from "jsonwebtoken";
import { env } from "../config/env";
import { token } from "morgan";

/**
 * @description generates acess and refresh tokens for our digital sign.
*/

export interface jwtPayload {
      userId: string;
      role: string;
}


export function signAcessToken(payload: jwtPayload): string {
      const options: SignOptions = {
            expiresIn: env.jwtAccessExpiresIn as SignOptions["expiresIn"],
      };

      return jwt.sign(payload, env.jwtAccessSecret, options);
}

export function signRefreshToken(payload: jwtPayload): string {
      const options: SignOptions = {
            expiresIn: env.jwtRefreshExpiresIn as SignOptions["expiresIn"],
      };

      return jwt.sign(payload, env.jwtRefreshSecret, options);
}

export function verifyAcessToken(token: string): jwtPayload {
      return jwt.verify(token, env.jwtAccessSecret) as jwtPayload
}

export function verRefreshessToken(token: string): jwtPayload {
      return jwt.verify(token, env.jwtRefreshSecret) as jwtPayload;
}

