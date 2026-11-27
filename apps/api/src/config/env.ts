import dotenv from "dotenv";
import path from "path";

dotenv.config({
      path: path.resolve(__dirname, "../../.env"),
});


/**
 * @description is any secret misses don't let the server to start
 */

if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is not defined.");
}

if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
      throw new Error("JWT Access or Refresh token secret key isn't defined.");
}

export const env = {
      nodeEnv: process.env.NODE_ENV || "development",
      port: Number(process.env.PORT) || 5000,
      clientUrl: process.env.CLIENT_URL || "http://localhost:5173",
      databaseUrl: process.env.DATABASE_URL,
      directUrl: process.env.DIRECT_URL || process.env.DATABASE_URL,
      jwtAccessSecret: process.env.JWT_ACCESS_SECRET,
      jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
      jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
      jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
      redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
      isProd: process.env.NODE_ENV === "production",
      FRONTEND_URL: process.env.FRONTEND_URL || "http://localhost:3000",
      GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || "",
      GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || "",
      GOOGLE_CALLBACK_URL:
            process.env.GOOGLE_CALLBACK_URL ||
            "http://localhost:4000/api/auth/google/callback",
};