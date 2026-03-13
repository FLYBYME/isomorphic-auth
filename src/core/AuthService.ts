import { mKDC } from './mKDC';
import { Context } from '@mesh-app/core';
import { IServiceActionRegistry } from '../types/auth.contract';

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
        ctx: Context<IServiceActionRegistry['auth.authenticate']['params']>
    ): Promise<IServiceActionRegistry['auth.authenticate']['returns']> {
        const result = await this.mkdc.authenticate(ctx.params);
        return { token: result.token };
    }

    /**
     * Issue a Service Ticket (ST) using a TGT.
     */
    async getServiceTicket(
        ctx: Context<IServiceActionRegistry['auth.getServiceTicket']['params']>
    ): Promise<IServiceActionRegistry['auth.getServiceTicket']['returns']> {
        const result = await this.mkdc.issueServiceTicket(ctx.params);
        return { token: result.token };
    }
}
