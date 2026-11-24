import bcrypt from "bcryptjs";
import { PrismaClient, Role } from "@prisma/client";
import { AppError } from "../../utils/AppError";
import {
      jwtPayload,
      signAcessToken,
      signRefreshToken,
      verifyRefreshToken
} from "../../utils/jwt";

import {
      blacklistRefreshToken,
      isRefreshTokenBlacklisted
} from "./blacklist.service";

import { prisma } from "../../lib/prisma";

export interface ResigterInput {
      email: string;
      password: string;
      name?: string;
      phone?: string;
      role?: Role;
}

export interface LoginInput {
      email: string;
      password: string;
}

function issueTokenPair(payload: jwtPayload) {
      const accessToken = signAcessToken(payload);
      const refreshToken = signRefreshToken(payload);

      return { accessToken, refreshToken };
}

/**
 * 
 * @param input interface of RegisterInput fields
 * @description register user
 * @returns registered user with access and refresh Tokens
 */
export async function registerUser(input: ResigterInput) {
      const email = input.email.trim().toLocaleLowerCase();

      const exsistingUser = await prisma.user.findUnique({
            where: { email: email }
      });

      if (exsistingUser) {
            throw new AppError("User Already Exsists", 409);
      }

      const passwordHash = await bcrypt.hash(input.password, 12);
      const assignedRole: Role = input.role === Role.SELLER ? Role.SELLER : Role.USER;

      const user = await prisma.user.create({
            data: {
                  email: email,
                  passwordHash,
                  name: input.name?.trim() || null,
                  role: assignedRole
            },
            select: {
                  id: true,
                  email: true,
                  name: true,
                  role: true,
                  createdAt: true,
                  updateAt: true,
            }
      });

      const tokens = issueTokenPair({ userId: user.id, role: user.role });
      return { user, ...tokens };
}

/**
 * 
 * @param input Interface of loign input fields 
 * @description Login a User
 * @returns logged in user with the acess and refresh tokens
 */
export async function loginUser(input: LoginInput) {
      const email = input.email.trim().toLocaleLowerCase();

      const userInfo = await prisma.user.findUnique({
            where: { email: email }
      });

      if (!userInfo) {
            throw (new AppError("User not even exsists. Make sure to register first!", 401));
      }

      const isValiPass = await bcrypt.compare(input.password, userInfo.passwordHash);

      if (!isValiPass) {
            throw (new AppError("Invalid email or password", 401));
      }

      const tokens = issueTokenPair({ userId: userInfo.id, role: userInfo.role });

      const user = {
            id: userInfo.id,
            email: userInfo.email,
            name: userInfo.name,
            phone: userInfo.phone,
            role: userInfo.role,
            createdAt: userInfo.createdAt,
            updateAt: userInfo.updateAt,
      };

      return { user, ...tokens };
}

export async function logOutUser(refreshToken?: string): Promise<void> {
      await blacklistRefreshToken(refreshToken);
}

/**
 * 
 * @param userId 
 * @returns retrives the current logged i user used for hydration at frontend
 */
export async function getCurrentUser(userId: string) {
      const user = await prisma.user.findUnique({
            where: { id: userId },
            select: {
                  id: true,
                  email: true,
                  name: true,
                  phone: true,
                  createdAt: true,
                  updateAt: true,
            },
      });

      if (!user) {
            throw new AppError("User not found", 404);
      }

      return user;
}

/**
 * @param refreshToken string type token
 * @description verify the exsisting refreshtoken and generate a new acess and refresh token
 * @returns newly generated acess and refresh tokens
 */
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

      //check whether the current refresh token is blacklisted or not
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