import crypto from "crypto";
import jwt from "jsonwebtoken";
import { redis } from "../../lib/redis";


function hashToken(token: string): string {
      return crypto.createHash("sha256").update(token).digest("hex");
}

/**
 * @param token only a valid live jwt token will stay in redis if its expired remove 
 * from the redis becaue jwt.verify() will reject it any way if expired
 * @returns TTL (time to live) for a blacklisted token
 */
function getTimeToLive(token: string): number {
      const decoded = jwt.decode(token) as { exp?: number } || null;
      if (!decoded?.exp) return 0;

      return Math.max(0, decoded.exp - Math.floor(Date.now() / 1000));
}

export async function blacklistRefreshToken(
      refreshToken: string | undefined
): Promise<void> {
      if (!refreshToken) return;

      const ttlSeconds = getTimeToLive(refreshToken);
      if (ttlSeconds <= 0) return;

      const key = `bl:refresh:${hashToken(refreshToken)}`;
      await redis.set(key, "1", "EX", ttlSeconds);
}

export async function isRefreshTokenBlacklisted(
      refreshToken: string
): Promise<boolean> {
      const key = `bl:refresh:${hashToken(refreshToken)}`;
      const exists = await redis.exists(key);
      return exists === 1;
}