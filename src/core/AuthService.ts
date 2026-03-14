import { z } from 'zod';
import { mKDC } from './mKDC';
import { Context } from 'isomorphic-registry';
// IServiceActionRegistry is a global interface, no need to import it if it's not exported.
// However, since we are in a module, we might need to reference it or use the type directly.

/**
 * AuthService — Handles authentication and ticket issuance.
 * Strictly implements handlers using inferred types from the registry.
 */
export class AuthService {
    public readonly name = 'auth';

    constructor(private mkdc: mKDC) {}

    /**
     * Authenticate a node and issue a TGT.
     */
    async authenticate(
        ctx: Context<z.infer<IServiceActionRegistry['auth.authenticate']['params']>>
    ): Promise<z.infer<IServiceActionRegistry['auth.authenticate']['returns']>> {
        const result = await this.mkdc.authenticate(ctx.params);
        return { token: result.token };
    }

    /**
     * Issue a Service Ticket (ST) using a TGT.
     */
    async getServiceTicket(
        ctx: Context<z.infer<IServiceActionRegistry['auth.getServiceTicket']['params']>>
    ): Promise<z.infer<IServiceActionRegistry['auth.getServiceTicket']['returns']>> {
        const result = await this.mkdc.issueServiceTicket(ctx.params);
        return { token: result.token };
    }
}
