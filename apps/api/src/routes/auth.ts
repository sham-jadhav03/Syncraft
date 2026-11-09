import { Router } from "express";
import bcrypt from "bcryptjs";
import { prisma } from "@syncraft/db";
import { loginSchema, registerSchema } from "@syncraft/shared";
import { env } from "../env";
import { HttpError } from "../lib/errors";
import { signAccess, signRefresh, verifyRefresh } from "../lib/tokens";
import { validate } from "../middleware/validate";

export const authRouter = Router();

const COOKIE = "syncraft_refresh";
const cookieOpts = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: env.NODE_ENV === "production",
  path: "/auth",
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

authRouter.post("/register", validate(registerSchema), async (req, res) => {
  const { email, name, password } = req.body;
  const normalized = email.toLowerCase();

  if (await prisma.user.findUnique({ where: { email: normalized } })) {
    throw new HttpError(409, "Email already registered");
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.$transaction(async (tx) => {
    const u = await tx.user.create({
      data: { email: normalized, name, passwordHash },
    });
    const ws = await tx.workspace.create({
      data: { name: `${name}'s workspace`, ownerId: u.id },
    });
    await tx.workspaceMember.create({
      data: { workspaceId: ws.id, userId: u.id, role: "OWNER" },
    });
    return u;
  });

  res.cookie(COOKIE, signRefresh(user.id), cookieOpts);
  res.status(201).json({
    user: { id: user.id, email: user.email, name: user.name },
    accessToken: signAccess(user.id),
  });
});

authRouter.post("/login", validate(loginSchema), async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });

  // Same message for both cases, so attackers can't discover which emails exist
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    throw new HttpError(401, "Invalid email or password");
  }

  res.cookie(COOKIE, signRefresh(user.id), cookieOpts);
  res.json({
    user: { id: user.id, email: user.email, name: user.name },
    accessToken: signAccess(user.id),
  });
});

authRouter.post("/refresh", async (req, res) => {
  const token = req.cookies?.[COOKIE];
  if (!token) throw new HttpError(401, "No refresh token");
  try {
    const { sub } = verifyRefresh(token);
    res.json({ accessToken: signAccess(sub!) });
  } catch {
    throw new HttpError(401, "Invalid refresh token");
  }
});

authRouter.post("/logout", (_req, res) => {
  res.clearCookie(COOKIE, { path: "/auth" });
  res.status(204).end();
});