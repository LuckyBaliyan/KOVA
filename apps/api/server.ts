import "dotenv/config";
import app from "./src/app";
import { prisma } from "./src/lib/prisma";
import { connectRedis } from "./src/lib/redis";

const PORT = Number(process.env.PORT) || 4000;


app.get("/health", (_req, res) => {
      res.status(200).json({
            success: true,
            port: Number(process.env.PORT) || 4000,
      });
});

async function startServer() {
      await connectRedis();

      app.listen(PORT, () => {
            console.log(`KOVA API running on port ${PORT}`);
      });
}

startServer();