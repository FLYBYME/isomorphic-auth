import { MeshTokenManager } from './MeshTokenManager';
import { IsomorphicCrypto } from '../utils/crypto';
import { TGTRequest, STRequest, TokenPayload } from '../types/auth.schema';
import { ILogger } from '../types/auth.types';

export type KDCCaller = (action: string, params: Record<string, unknown>, meta?: Record<string, unknown>) => Promise<any>;

/**
 * TicketManager — manages the lifecycle of TGT and ST tickets.
 */
export class TicketManager {
    private tgt: string | null = null;
    private tgtExpiration = 0;
    private stCache = new Map<string, string>();
    private renewalTimer: NodeJS.Timeout | null = null;

    constructor(
        private nodeID: string,
        private tokenManager: MeshTokenManager,
        private kdcCaller: KDCCaller,
        private logger: ILogger,
        private privateKey?: string
    ) { }

    /**
     * Bootstrap identity by requesting a TGT from the KDC.
     */
    async bootstrapIdentity(): Promise<void> {
        if (!this.privateKey) throw new Error('No private key available for identity bootstrap');

        this.logger.info('Bootstrapping identity...', { nodeID: this.nodeID });

        const nonce = IsomorphicCrypto.randomID(16);
        const signature = await IsomorphicCrypto.signEd25519(nonce, this.privateKey);

        const req: TGTRequest = {
            nodeID: this.nodeID,
            nonce,
            signature
        };

        try {
            const res = await this.kdcCaller('auth.authenticate', req as unknown as Record<string, unknown>);
            this.tgt = res.token || res.tgt;

            if (this.tgt) {
                const decoded = this.tokenManager.decode(this.tgt);
                if (decoded && decoded.exp) {
                    this.tgtExpiration = decoded.exp * 1000;
                    this.scheduleRenewal();
                    this.logger.info('Identity established. TGT acquired.');
                }
            }
        } catch (err: any) {
            this.logger.error('Identity bootstrap failed', { error: err.message });
            throw err;
        }
    }

    private scheduleRenewal(): void {
        if (this.renewalTimer) clearTimeout(this.renewalTimer);

        // Renew 5 minutes before expiration
        const renewIn = (this.tgtExpiration - Date.now()) - (5 * 60 * 1000);
        if (renewIn > 0) {
            this.renewalTimer = setTimeout(() => this.bootstrapIdentity(), renewIn);
        }
    }

    /**
     * Get a Service Ticket (ST) for a target node.
     */
    async getTicketFor(targetNodeID: string): Promise<string> {
        const cachedST = this.stCache.get(targetNodeID);
        if (cachedST) {
            const decoded = this.tokenManager.decode(cachedST);
            if (decoded && decoded.exp && (decoded.exp * 1000) > Date.now()) {
                return cachedST;
            }
            this.stCache.delete(targetNodeID);
        }

        // Memory Guard: Prune cache if it gets too large
        if (this.stCache.size > 100) {
            this.pruneSTCache();
        }

        if (!this.tgt) {
            throw new Error('No valid TGT available. Call bootstrapIdentity() first.');
        }

        const req: STRequest = {
            tgt: this.tgt,
            targetNodeID
        };

        const res = await this.kdcCaller('auth.getServiceTicket', req as unknown as Record<string, unknown>);
        const st = res.token || res.st;
        this.stCache.set(targetNodeID, st);

        return st;
    }

    private pruneSTCache(): void {
        const now = Date.now();
        for (const [nodeID, st] of this.stCache.entries()) {
            const decoded = this.tokenManager.decode(st);
            if (!decoded || !decoded.exp || (decoded.exp * 1000) <= now) {
                this.stCache.delete(nodeID);
            }
        }
        
        // If still too large, remove oldest
        if (this.stCache.size > 100) {
            const firstKey = this.stCache.keys().next().value;
            if (firstKey) this.stCache.delete(firstKey);
        }
    }

    stop(): void {
        if (this.renewalTimer) clearTimeout(this.renewalTimer);
        this.stCache.clear();
    }

    getTGT(): string | null {
        return this.tgt;
    }
}
