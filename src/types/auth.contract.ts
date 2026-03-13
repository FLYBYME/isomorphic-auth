import { z } from 'zod';
import { TGTRequestSchema, STRequestSchema } from './auth.schema';

/**
 * AuthContract — The formal Zod contract for the Authentication Service.
 * Injects types into the global IServiceActionRegistry.
 */
declare global {
    interface IServiceActionRegistry {
        'auth.authenticate': {
            params: typeof TGTRequestSchema;
            returns: z.ZodObject<{ token: z.ZodString }>;
        };
        'auth.getServiceTicket': {
            params: typeof STRequestSchema;
            returns: z.ZodObject<{ token: z.ZodString }>;
        };
    }
}

export const AuthContract = {
    name: 'auth',
    actions: {
        authenticate: {
            params: TGTRequestSchema,
            returns: z.object({
                token: z.string()
            })
        },
        getServiceTicket: {
            params: STRequestSchema,
            returns: z.object({
                token: z.string()
            })
        }
    }
};
