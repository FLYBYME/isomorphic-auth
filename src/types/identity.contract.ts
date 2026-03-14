import { z } from 'zod';
import { UserRegistrationSchema, UserLoginSchema, IdentitySettingsSchema } from './identity.schema';

/**
 * IdentityContract — The formal Zod contract for the Identity Service.
 * Injects types into the global MeshActionRegistry and ISettingsRegistry.
 */
declare global {
    interface MeshActionRegistry {
        'auth.identity.register': {
            params: typeof UserRegistrationSchema;
            returns: z.ZodObject<{ id: z.ZodString, email: z.ZodString }>;
        };
        'auth.identity.login': {
            params: typeof UserLoginSchema;
            returns: z.ZodObject<{ id: z.ZodString, token: z.ZodString }>;
        };
    }

    interface ISettingsRegistry {
        'auth.identity': typeof IdentitySettingsSchema;
    }
}

export const IdentityContract = {
    name: 'auth.identity',
    settings: IdentitySettingsSchema,
    actions: {
        register: {
            params: UserRegistrationSchema,
            returns: z.object({
                id: z.string(),
                email: z.string()
            })
        },
        login: {
            params: UserLoginSchema,
            returns: z.object({
                id: z.string(),
                token: z.string()
            })
        }
    }
};
