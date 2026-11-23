import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./modules/auth/auth.routes";
import { errorHandler } from "./middlewares/error.middleware";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRouter);

app.use(errorHandler);

export default app;
