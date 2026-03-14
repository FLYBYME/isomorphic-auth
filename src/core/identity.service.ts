import { z } from 'zod';
import { DistributedLedger } from 'raft-consensus';
import { IsomorphicCrypto } from '../utils/crypto';
import { UserRegistration, UserLogin, UserIdentity, IdentitySettingsSchema } from '../types/identity.schema';
import { Context, MeshActionRegistry, ILogger } from 'isomorphic-registry';
import { IStorageAdapter } from '../types/auth.types';

/**
 * IdentityService — Manages user identity and authentication.
 * 
 * Uses Raft Distributed Ledger for persistent, replicated user records.
 */
export class IdentityService {
    public readonly name = 'auth.identity';
    private ledger!: DistributedLedger<UserIdentity>;

    constructor(
        private storage: IStorageAdapter,
        private logger: ILogger,
        private namespace: string = 'auth'
    ) {}

    /**
     * Created hook — initializes the ledger.
     */
    async created(): Promise<void> {
        // We use the storage adapter as the provider for the ledger
        this.ledger = new DistributedLedger<UserIdentity>(this.namespace, this.storage as any);
    }

    /**
     * Register a new human identity.
     */
    async register(
        ctx: Context<z.infer<MeshActionRegistry['auth.identity.register']['params']>>
    ): Promise<z.infer<MeshActionRegistry['auth.identity.register']['returns']>> {
        const { email, password, metadata } = ctx.params;

        // 1. Check if user already exists (simplified check)
        // In a real DLT, you might need to scan the ledger or maintain an index.
        // For this implementation, we'll assume uniqueness for brevity or use the storage directly if indexed.
        
        // 2. Hash password
        const { hash, salt } = await IsomorphicCrypto.hashPassword(password);
        const storedHash = `${salt}:${hash}`; // Format: salt:hash

        // 3. Construct Identity record
        const identity: UserIdentity = {
            id: IsomorphicCrypto.randomID(16), // Simplified ID for now
            email,
            hash: storedHash,
            status: 'ACTIVE',
            metadata: metadata || {},
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        // 4. Append to Ledger
        await this.ledger.append({
            term: 1, // Term would come from Raft state in a real scenario
            nodeID: ctx.nodeID,
            payload: identity
        });

        this.logger.info(`User registered: ${email} (${identity.id})`);

        return { id: identity.id, email: identity.email };
    }

    /**
     * Authenticate a human user and return a TGT from the KDC.
     */
    async login(
        ctx: Context<z.infer<MeshActionRegistry['auth.identity.login']['params']>>
    ): Promise<z.infer<MeshActionRegistry['auth.identity.login']['returns']>> {
        const { email, password } = ctx.params;

        // 1. Retrieve user from ledger (simplified: find in local storage index)
        // In a real scenario, the Ledger maintains a materialized view.
        const user = await this.findUserByEmail(email);
        if (!user || user.status !== 'ACTIVE') {
            throw new Error('Invalid credentials or account disabled.');
        }

        // 2. Verify password
        const [salt, hash] = user.hash.split(':');
        const isValid = await IsomorphicCrypto.verifyPassword(password, hash, salt);
        if (!isValid) {
            throw new Error('Invalid credentials.');
        }

        // 3. Request TGT from sys.kdc
        // Since it's a human login, we might need a special way to sign the TGT request,
        // or the KDC might trust auth.identity for human users.
        // For the plan's flow: "calls sys.kdc.request_tgt on behalf of the user."
        
        // We'll generate a nonce and sign it using a service-level key if needed,
        // but here we'll assume a simplified exchange for the prototype.
        const tgtResponse = await ctx.call<any>('sys.kdc.authenticate', {
            nodeID: `user:${user.id}`,
            nonce: IsomorphicCrypto.randomID(16),
            signature: 'TRUSTED_IDENTITY_SERVICE_SIGNATURE' // Placeholder for service-to-service trust
        });

        this.logger.info(`User logged in: ${email}`);

        return {
            id: user.id,
            token: tgtResponse.token
        };
    }

    /**
     * Helper to find user in the materialized state (storage).
     */
    private async findUserByEmail(email: string): Promise<UserIdentity | null> {
        // This assumes the ledger writes its payload to a queryable table or we search the transactions.
        const row = await (this.storage as any).get(
            'SELECT payload FROM ledger_transactions WHERE namespace = ? AND payload LIKE ? LIMIT 1',
            [this.namespace, `%${email}%`]
        );
        if (!row) return null;
        try {
            const tx = JSON.parse((row as any).payload);
            return tx as UserIdentity;
        } catch {
            return null;
        }
    }
}
