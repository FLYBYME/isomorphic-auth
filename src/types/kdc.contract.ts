import { z } from 'zod';
import { TGTRequestSchema, STRequestSchema } from './auth.schema';
import { ValidatePACParamsSchema, ValidatePACResponseSchema, KDCSettingsSchema } from './kdc.schema';

/**
 * KDCContract — The formal Zod contract for the Key Distribution Center.
 * Injects types into the global MeshActionRegistry and ISettingsRegistry.
 */
declare global {
    interface MeshActionRegistry {
        'sys.kdc.authenticate': {
            params: typeof TGTRequestSchema;
            returns: z.ZodObject<{ token: z.ZodString }>;
        };
        'sys.kdc.getServiceTicket': {
            params: typeof STRequestSchema;
            returns: z.ZodObject<{ token: z.ZodString }>;
        };
        'sys.kdc.validate_pac': {
            params: typeof ValidatePACParamsSchema;
            returns: typeof ValidatePACResponseSchema;
        };
    }

    interface ISettingsRegistry {
        'sys.kdc': typeof KDCSettingsSchema;
    }
}

export const KDCContract = {
    name: 'sys.kdc',
    settings: KDCSettingsSchema,
    actions: {
        authenticate: {
            params: TGTRequestSchema,
            returns: z.object({ token: z.string() })
        },
        getServiceTicket: {
            params: STRequestSchema,
            returns: z.object({ token: z.string() })
        },
        validate_pac: {
            params: ValidatePACParamsSchema,
            returns: ValidatePACResponseSchema
        }
    }
};
