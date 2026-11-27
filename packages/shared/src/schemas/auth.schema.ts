import { z } from "zod";

export const RoleSchema = z.enum(["BUYER", "SELLER"]);

export const RegisterUserSchema = z
      .object({
            name: z
                  .string()
                  .trim()
                  .min(2, "Full name must be at least 2 characters")
                  .max(60, "Full name is too long")
                  .optional(),
            email: z.string().trim().toLowerCase().email("Invalid email address"),
            password: z
                  .string()
                  .min(8, "Password must be at least 8 characters")
                  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
                  .regex(/[0-9]/, "Password must contain at least one number")
                  .optional(),
            phone: z
                  .string()
                  .trim()
                  .regex(/^[+0-9\s-]{8,15}$/, "Invalid phone number")
                  .optional()
                  .or(z.literal("")),
            role: RoleSchema.optional(),
            googleId: z.string().trim().min(1).optional(),
            avatarUrl: z.string().trim().url("Invalid avatar URL").optional(),
      })
      .superRefine((data, ctx) => {
            // Toggle: agar googleId nahi hai toh password mandatory hai; googleId ho toh password skip
            if (!data.googleId && !data.password) {
                  ctx.addIssue({
                        code: z.ZodIssueCode.custom,
                        path: ["password"],
                        message: "Password is required when registering without Google",
                  });
            }
      });

export const LoginSchema = z.object({
      email: z.string().trim().toLowerCase().email("Invalid email address"),
      password: z.string().min(1, "Password is required"),
});

export type RoleInput = z.infer<typeof RoleSchema>;
export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;