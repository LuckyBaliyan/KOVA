import bcrypt from "bcryptjs";
import { Role } from "@prisma/client";
import { AppError } from "../../utils/AppError";
import {
      jwtPayload,
      signAcessToken,
      signRefreshToken,
      verifyRefreshToken,
} from "../../utils/jwt";
import {
      blacklistRefreshToken,
      isRefreshTokenBlacklisted,
} from "./blacklist.service";
import { prisma } from "../../lib/prisma";

export interface RegisterInput {
      email: string;
      password?: string;
      name?: string;
      phone?: string;
      role?: Role;
      googleId?: string;
      avatarUrl?: string;
}

export interface LoginInput {
      email: string;
      password: string;
}

export interface GoogleAuthInput {
      googleId: string;
      email: string;
      name?: string | null;
      avatarUrl?: string | null;
      requestedRole?: Role;
}

const safeUserSelect = {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatarUrl: true,
      role: true,
      createdAt: true,
      updateAt: true,
} as const;

function issueTokenPair(payload: jwtPayload) {
      const accessToken = signAcessToken(payload);
      const refreshToken = signRefreshToken(payload);

      return { accessToken, refreshToken };
}

export async function registerUser(input: RegisterInput) {
      const email = input.email.trim().toLowerCase();

      const existingUser = await prisma.user.findUnique({
            where: { email },
      });

      if (existingUser) {
            throw new AppError("User already exists", 409);
      }

      if (!input.googleId && !input.password) {
            throw new AppError("Password is required", 400);
      }

      const passwordHash = input.password
            ? await bcrypt.hash(input.password, 12)
            : null;

      const assignedRole: Role =
            input.role === Role.SELLER ? Role.SELLER : Role.BUYER;

      const user = await prisma.user.create({
            data: {
                  email,
                  passwordHash,
                  googleId: input.googleId ?? null,
                  avatarUrl: input.avatarUrl ?? null,
                  name: input.name?.trim() || null,
                  phone: input.phone?.trim() || null,
                  role: assignedRole,
            },
            select: safeUserSelect,
      });

      const tokens = issueTokenPair({ userId: user.id, role: user.role });
      return { user, ...tokens };
}

export async function loginUser(input: LoginInput) {
      const email = input.email.trim().toLowerCase();

      const userInfo = await prisma.user.findUnique({
            where: { email },
      });

      if (!userInfo) {
            throw new AppError(
                  "User does not exist. Make sure to register first!",
                  401
            );
      }

      // Guard for password-less Google accounts + narrows passwordHash to string
      if (!userInfo.passwordHash) {
            throw new AppError(
                  "This account uses Google Sign-In. Please continue with Google or set a password in profile settings.",
                  400
            );
      }

      const isValidPass = await bcrypt.compare(input.password, userInfo.passwordHash);

      if (!isValidPass) {
            throw new AppError("Invalid email or password", 401);
      }

      const tokens = issueTokenPair({ userId: userInfo.id, role: userInfo.role });

      const user = {
            id: userInfo.id,
            email: userInfo.email,
            name: userInfo.name,
            phone: userInfo.phone,
            avatarUrl: userInfo.avatarUrl,
            role: userInfo.role,
            createdAt: userInfo.createdAt,
            updateAt: userInfo.updateAt,
      };

      return { user, ...tokens };
}

export async function googleAuthUser(input: GoogleAuthInput) {
      const email = input.email.trim().toLowerCase();
      const googleId = input.googleId.trim();

      let user = await prisma.user.findUnique({
            where: { googleId },
            select: safeUserSelect,
      });

      if (!user) {
            const existingByEmail = await prisma.user.findUnique({
                  where: { email },
            });

            if (existingByEmail) {
                  // Link Google account to existing local user; preserve existing role
                  user = await prisma.user.update({
                        where: { id: existingByEmail.id },
                        data: {
                              googleId,
                              name: existingByEmail.name ?? (input.name?.trim() || null),
                              avatarUrl: existingByEmail.avatarUrl ?? (input.avatarUrl || null),
                        },
                        select: safeUserSelect,
                  });
            } else {
                  const assignedRole: Role =
                        input.requestedRole === Role.SELLER ? Role.SELLER : Role.BUYER;

                  user = await prisma.user.create({
                        data: {
                              email,
                              googleId,
                              passwordHash: null,
                              name: input.name?.trim() || null,
                              avatarUrl: input.avatarUrl || null,
                              role: assignedRole,
                        },
                        select: safeUserSelect,
                  });
            }
      } else if (!user.avatarUrl && input.avatarUrl) {
            user = await prisma.user.update({
                  where: { id: user.id },
                  data: { avatarUrl: input.avatarUrl },
                  select: safeUserSelect,
            });
      }

      const tokens = issueTokenPair({ userId: user.id, role: user.role });
      return { user, ...tokens };
}

export async function logOutUser(refreshToken?: string): Promise<void> {
      await blacklistRefreshToken(refreshToken);
}

export async function getCurrentUser(userId: string) {
      const user = await prisma.user.findUnique({
            where: { id: userId },
            select: safeUserSelect,
      });

      if (!user) {
            throw new AppError("User not found", 404);
      }

      return user;
}

export async function refreshSession(refreshToken: string | undefined) {
      if (!refreshToken) {
            throw new AppError("Refresh token missing", 401);
      }

      let decoded: jwtPayload;
      try {
            decoded = verifyRefreshToken(refreshToken);
      } catch {
            throw new AppError("Invalid or expired refresh token", 401);
      }

      const revoked = await isRefreshTokenBlacklisted(refreshToken);
      if (revoked) {
            throw new AppError("Refresh token has been revoked", 401);
      }

      const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: { id: true, role: true },
      });

      if (!user) {
            throw new AppError("User no longer exists", 401);
      }

      return issueTokenPair({ userId: user.id, role: user.role });
}