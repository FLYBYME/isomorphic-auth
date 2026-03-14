import { MeshTokenManager } from './MeshTokenManager';
import { IsomorphicCrypto } from '../utils/crypto';
import { TGTRequest, STRequest, TokenPayload } from '../types/auth.schema';
import { ILogger, IStorageAdapter } from '../types/auth.types';

/**
 * mKDC — Mesh Key Distribution Center logic.
 * Handles node authentication and ticket issuance.
 */
export class mKDC {
    constructor(
        private nodeID: string,
        private tokenManager: MeshTokenManager,
        private storage: IStorageAdapter,
        private logger: ILogger
    ) { }

    /**
     * Authenticate a node via Ed25519 signature and issue a TGT.
     */
    async authenticate(req: TGTRequest): Promise<{ token: string }> {
        const node = await this.storage.getNode(req.nodeID);
        if (!node || node.status === 'revoked') {
            throw new Error(`Node ${req.nodeID} is not registered or revoked.`);
        }

        const isValid = await IsomorphicCrypto.verifyEd25519(
            req.signature,
            req.nonce,
            node.publicKey
        );

        if (!isValid) {
            this.logger.warn(`Authentication failed for node ${req.nodeID}: Invalid signature.`);
            throw new Error('Invalid signature.');
        }

        this.logger.info(`Node ${req.nodeID} successfully authenticated. Issuing TGT.`);

        const token = await this.tokenManager.sign({
            type: 'TGT',
            sub: req.nodeID,
            capabilities: node.capabilities
        });

        return { token };
    }

    /**
     * Issue a Service Ticket (ST) using a valid TGT.
     */
    async issueServiceTicket(req: STRequest): Promise<{ token: string }> {
        const decodedTGT = await this.tokenManager.verify(req.tgt);
        if (!decodedTGT || decodedTGT.type !== 'TGT') {
            throw new Error('Invalid or expired TGT.');
        }

        const sourceNodeID = decodedTGT.sub;

        const targetNode = await this.storage.getNode(req.targetNodeID);
        if (!targetNode || targetNode.status === 'revoked') {
            throw new Error(`Target node ${req.targetNodeID} is not available.`);
        }

        this.logger.debug(`Issuing ST: ${sourceNodeID} -> ${req.targetNodeID}`);

        const token = await this.tokenManager.sign({
            type: 'ST',
            sub: sourceNodeID,
            aud: req.targetNodeID
        }, 900); // 15m default ST expiry

        return { token };
    }
}
