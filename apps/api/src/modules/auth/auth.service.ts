import bcrypt from "bcryptjs";
import { PrismaClient, Role } from "@prisma/client";
import { AppError } from "../../utils/AppError";
import {
      jwtPayload,
      signAcessToken,
      signRefreshToken,
      verifyRefreshToken
} from "../../utils/jwt";

import { prisma } from "../../lib/prisma";

/**
 * @description create and retrive user in Db and issue new tokens
 */

export interface ResigterInput {
      email: string;
      password: string;
      name?: string;
      role?: Role;
}

function issueTokenPair(payload: jwtPayload) {
      const accessToken = signAcessToken(payload);
      const refreshToken = signRefreshToken(payload);

      return { accessToken, refreshToken };
}

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


//loign, logout .....


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

      const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: { id: true, role: true },
      });

      if (!user) {
            throw new AppError("User no longer exists", 401);
      }

      return issueTokenPair({ userId: user.id, role: user.role });
}