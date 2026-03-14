import { z } from 'zod';

/**
 * Zod Schemas for Authentication and Authorization.
 */

export const TGTRequestSchema = z.object({
    nodeID: z.string(),
    nonce: z.string(),
    signature: z.string(),
});

export const STRequestSchema = z.object({
    tgt: z.string(),
    targetNodeID: z.string(),
});

export const VerifyTokenParamsSchema = z.object({
    token: z.string(),
});

export const TokenPayloadSchema = z.object({
    iss: z.string(),
    iat: z.number().optional(),
    exp: z.number().optional(),
    sub: z.string(),
    type: z.enum(['TGT', 'ST', 'join', 'attach']),
    capabilities: z.array(z.string()).optional(),
    aud: z.string().optional(),
    sessionKey: z.string().optional(),
    jti: z.string().optional(),
    tenant_id: z.string().optional(),
});

export const NodeSchema = z.object({
    nodeID: z.string(),
    publicKey: z.string(),
    capabilities: z.array(z.string()).default([]),
    lastSeen: z.number().int().optional(),
    status: z.enum(['active', 'offline', 'revoked']).default('active'),
});

export const AuthSettingsSchema = z.object({
    issuer: z.string().default('isomorphic-auth-gateway'),
    tokenTTL: z.number().default(3600), // 1 hour
    secret: z.string().optional().describe('JWT signing secret (deprecated for Ed25519)'),
});

export type TGTRequest = z.infer<typeof TGTRequestSchema>;
export type STRequest = z.infer<typeof STRequestSchema>;
export type TokenPayload = z.infer<typeof TokenPayloadSchema>;
export type AuthSettings = z.infer<typeof AuthSettingsSchema>;
export type NodeRecord = z.infer<typeof NodeSchema>;
