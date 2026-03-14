import { z } from 'zod';
import { mKDC } from './mKDC';
import { MeshTokenManager } from './MeshTokenManager';
import { IStorageAdapter, ILogger } from '../types/auth.types';
import { Context, MeshActionRegistry } from 'isomorphic-registry';
import { KDCSettingsSchema, ValidatePACResponse } from '../types/kdc.schema';

/**
 * KDCService — Key Distribution Center Service.
 * 
 * Implements the sys.kdc domain for the mesh.
 */
export class KDCService {
    public readonly name = 'sys.kdc';
    private mkdc!: mKDC;

    constructor(
        private storage: IStorageAdapter,
        private logger: ILogger,
        private issuer: string = 'sys.kdc'
    ) {}

    /**
     * Created hook — initialized the underlying logic.
     */
    async created(): Promise<void> {
        // In a real scenario, these would come from providers or settings.
        const tokenManager = new MeshTokenManager(this.issuer);
        this.mkdc = new mKDC(this.issuer, tokenManager, this.storage, this.logger);
    }

    /**
     * Authenticate a node and issue a TGT.
     */
    async authenticate(
        ctx: Context<z.infer<MeshActionRegistry['sys.kdc.authenticate']['params']>>
    ): Promise<z.infer<MeshActionRegistry['sys.kdc.authenticate']['returns']>> {
        const result = await this.mkdc.authenticate(ctx.params);
        return { token: result.token };
    }

    /**
     * Issue a Service Ticket (ST) using a valid TGT.
     */
    async getServiceTicket(
        ctx: Context<z.infer<MeshActionRegistry['sys.kdc.getServiceTicket']['params']>>
    ): Promise<z.infer<MeshActionRegistry['sys.kdc.getServiceTicket']['returns']>> {
        const result = await this.mkdc.issueServiceTicket(ctx.params);
        return { token: result.token };
    }

    /**
     * Synchronous verification endpoint for high-security PAC validation.
     */
    async validate_pac(
        ctx: Context<z.infer<MeshActionRegistry['sys.kdc.validate_pac']['params']>>
    ): Promise<z.infer<MeshActionRegistry['sys.kdc.validate_pac']['returns']>> {
        const { subjectID } = ctx.params;
        const record = await this.storage.getNode(subjectID);
        
        if (!record || record.status === 'revoked') {
            return { status: 'REVOKED', valid: false };
        }

        return { 
            status: record.status.toUpperCase() as any, 
            valid: record.status === 'active' 
        };
    }
}
