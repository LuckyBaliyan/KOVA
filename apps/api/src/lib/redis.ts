import { error } from "console";
import { futimesSync } from "fs";
import Redis from "ioredis";
import { env } from "../config/env";

export const redis = new Redis(env.redisUrl, {
      maxRetriesPerRequest: 2,
      enableReadyCheck: true,
      lazyConnect: true,
});


redis.on("connect", () => {
      console.log("Redis connecting...");
});

redis.on("ready", () => {
      console.log("Redis connected and ready");
});

redis.on("error", (error) => {
      console.log(error.message || "redis connection failed!");
});

export async function connectRedis(): Promise<void> {
      if (redis.status === "ready" || redis.status === "connecting") return;

      await redis.connect();
}


export async function disconnectRedis(): Promise<void> {
      if (redis.status === "end") return;
      await redis.quit();
}