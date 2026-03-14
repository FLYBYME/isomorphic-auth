import { z } from 'zod';

/**
 * Identity-specific schema definitions.
 */

export const UserRegistrationSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    metadata: z.record(z.unknown()).optional(),
});

export const UserLoginSchema = z.object({
    email: z.string().email(),
    password: z.string(),
});

export const UserIdentitySchema = z.object({
    id: z.string().uuid(),
    email: z.string().email(),
    hash: z.string(), // Secure hash (PBKDF2/Argon2)
    status: z.enum(['ACTIVE', 'DISABLED', 'REVOKED']).default('ACTIVE'),
    metadata: z.record(z.unknown()).optional(),
    createdAt: z.number(),
    updatedAt: z.number(),
});

export const IdentitySettingsSchema = z.object({
    passwordMinLength: z.number().default(8),
    sessionTTL: z.number().default(3600),
});

export type UserRegistration = z.infer<typeof UserRegistrationSchema>;
export type UserLogin = z.infer<typeof UserLoginSchema>;
export type UserIdentity = z.infer<typeof UserIdentitySchema>;
export type IdentitySettings = z.infer<typeof IdentitySettingsSchema>;
