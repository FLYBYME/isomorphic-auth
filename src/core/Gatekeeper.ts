import { MeshTokenManager } from './MeshTokenManager';
import { TokenPayload } from '../types/auth.schema';
import { ILogger } from '../types/auth.types';

/**
 * Gatekeeper — enforces strict ticket validation and audience checks for incoming calls.
 */
export class Gatekeeper {
    constructor(
        private nodeID: string,
        private tokenManager: MeshTokenManager,
        private logger: ILogger,
        private kdcPublicKey?: string
    ) {}

    /**
     * Verify a Service Ticket (ST) for an incoming request.
     */
    async verifyServiceTicket(ticket: string): Promise<TokenPayload | null> {
        try {
            const payload = await this.tokenManager.verify(ticket, this.kdcPublicKey);
            
            if (!payload) {
                this.logger.warn('Invalid ticket signature or expired ticket.');
                return null;
            }

            // 1. Strict Ticket Type Check
            if (payload.type !== 'ST' && payload.type !== 'TGT') {
                this.logger.warn(`Incorrect ticket type: expected ST/TGT, got ${payload.type}`);
                return null;
            }

            // 2. Strict Audience Check (for ST)
            if (payload.type === 'ST' && payload.aud !== this.nodeID) {
                this.logger.error(`Audience mismatch: expected ${this.nodeID}, got ${payload.aud}`);
                return null;
            }

            return payload;
        } catch (err) {
            this.logger.error('Error during ticket verification', { error: (err as any).message });
            return null;
        }
    }

    /**
     * Optional: Synchronous high-security PAC check-back (requires network access).
     */
    async checkPAC(subjectID: string, kdcCaller: (action: string, params: any) => Promise<any>): Promise<boolean> {
        try {
            const res = await kdcCaller('sys.kdc.validate_pac', { subjectID });
            return res.valid === true;
        } catch (err) {
            this.logger.error('PAC check-back failed', { subjectID, error: (err as any).message });
            return false;
        }
    }
}
