import { z } from 'zod';
import { TGTRequestSchema, STRequestSchema, TokenPayloadSchema } from './auth.schema';

/**
 * KDC-specific schema definitions.
 */

export const KDCSettingsSchema = z.object({
    issuer: z.string().default('sys.kdc'),
    tgtTTL: z.number().default(86400), // 24 hours
    stTTL: z.number().default(900),    // 15 minutes
});

export const ValidatePACParamsSchema = z.object({
    subjectID: z.string(),
});

export const ValidatePACResponseSchema = z.object({
    status: z.enum(['ACTIVE', 'DISABLED', 'REVOKED']),
    valid: z.boolean(),
});

export type KDCSettings = z.infer<typeof KDCSettingsSchema>;
export type ValidatePACParams = z.infer<typeof ValidatePACParamsSchema>;
export type ValidatePACResponse = z.infer<typeof ValidatePACResponseSchema>;
