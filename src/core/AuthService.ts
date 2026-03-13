import { mKDC } from './mKDC';
import { TGTRequest, STRequest } from '../types/auth.schema';
import { Context } from '../../../isomorphic-core/src/contracts/Context';

/**
 * AuthService — Handles authentication and ticket issuance via mKDC.
 */
export class AuthService {
    public readonly name = 'auth';

    constructor(private mkdc: mKDC) {}

    /**
     * Authenticate a node and issue a TGT.
     */
    async authenticate(ctx: Context<TGTRequest>): Promise<{ token: string }> {
        return await this.mkdc.authenticate(ctx.params);
    }

    /**
     * Issue a Service Ticket (ST) using a TGT.
     */
    async getServiceTicket(ctx: Context<STRequest>): Promise<{ token: string }> {
        return await this.mkdc.issueServiceTicket(ctx.params);
    }
}
