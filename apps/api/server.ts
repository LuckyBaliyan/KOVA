import "dotenv/config";
import app from "./src/app";
import { prisma } from "./src/lib/prisma";

const PORT = Number(process.env.PORT) || 4000;


app.get("/health", (_req, res) => {
      res.status(200).json({
            success: true,
            port: Number(process.env.PORT) || 4000,
      });
});

const server = app.listen(PORT, () => {
      console.log(`KOVA API running on port ${PORT}`);
});

async function shutdown(signal: string) {
      console.log(`${signal} received. Closing server...`);
      server.close(async () => {
            await prisma.$disconnect();
            process.exit(0);
      });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));