import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { env } from "./env";
import { authRouter } from "./routes/auth";
import { meRouter } from "./routes/me";
import { errorHandler } from "./middleware/error";

export const app = express();

app.use(helmet());
app.use(cors({ origin: env.WEB_ORIGIN, credentials: true }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.use(
  "/auth",
  rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 }), // in-memory for now; move to Redis later
  authRouter,
);
app.use("/me", meRouter);

app.use(errorHandler); // must be last