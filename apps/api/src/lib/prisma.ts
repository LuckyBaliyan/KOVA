import { PrismaClient } from "@prisma/client";

/**
  @description making a global instance of pirsma for whole app 
*/

export const prisma = new PrismaClient();