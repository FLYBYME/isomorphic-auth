import { z } from 'zod';
import { TGTRequestSchema, STRequestSchema, TokenPayloadSchema } from './auth.schema';

/**
 * AuthContract — The formal Zod contract for the Authentication Service.
 */
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
