import { MeshTokenManager } from '../src/core/MeshTokenManager';
import { TicketManager } from '../src/core/TicketManager';
import { SecurityManager } from '../src/core/SecurityManager';
import { RBAC } from '../src/core/RBAC';
import { IsomorphicCrypto } from '../src/utils/crypto';

describe('Additional Coverage Tests', () => {
    let keys: { publicKey: string, privateKey: string };
    
    beforeAll(async () => {
        const keyPair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
        const pub = await globalThis.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const priv = await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        keys = {
            publicKey: IsomorphicCrypto.toBase64(new Uint8Array(pub)),
            privateKey: IsomorphicCrypto.toBase64(new Uint8Array(priv))
        };
    });

    describe('TicketManager', () => {
        let tokenManager: MeshTokenManager;
        let mockLogger: any;
        
        let tms: TicketManager[] = [];
        
        beforeEach(() => {
            tokenManager = new MeshTokenManager('kdc-node', keys);
            mockLogger = {
                debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn()
            };
            tms = [];
        });

        afterEach(() => {
            for (const tm of tms) tm.stop();
        });

        test('should throw error on bootstrapIdentity failure', async () => {
            const mockCaller = jest.fn().mockRejectedValue(new Error('KDC Error'));
            const tm = new TicketManager('my-node', tokenManager, mockCaller, mockLogger, keys.privateKey);
            tms.push(tm);
            
            await expect(tm.bootstrapIdentity()).rejects.toThrow('KDC Error');
            expect(mockLogger.error).toHaveBeenCalled();
        });

        test('should getTicketFor target', async () => {
            const mockCaller = jest.fn().mockImplementation(async (action) => {
                if (action === 'sys.kdc.authenticate') {
                    const tgt = await tokenManager.sign({ type: 'TGT', sub: 'my-node', capabilities: [] });
                    return { token: tgt };
                }
                if (action === 'sys.kdc.getServiceTicket') {
                    const st = await tokenManager.sign({ type: 'ST', sub: 'my-node', aud: 'target-node' });
                    return { token: st };
                }
            });
            const tm = new TicketManager('my-node', tokenManager, mockCaller, mockLogger, keys.privateKey);
            tms.push(tm);
            
            await tm.bootstrapIdentity();
            const ticket = await tm.getTicketFor('target-node');
            expect(ticket).toBeDefined();

            // Fetch again should return from cache
            const ticket2 = await tm.getTicketFor('target-node');
            expect(ticket2).toBe(ticket);
        });

        test('should prune cache when exceeding 100 entries', async () => {
            const mockCaller = jest.fn().mockImplementation(async (action) => {
                if (action === 'sys.kdc.authenticate') return { token: await tokenManager.sign({ type: 'TGT', sub: 'my-node', capabilities: [] }) };
                if (action === 'sys.kdc.getServiceTicket') return { token: await tokenManager.sign({ type: 'ST', sub: 'my-node', aud: 'target' }) };
            });
            const tm = new TicketManager('my-node', tokenManager, mockCaller, mockLogger, keys.privateKey);
            tms.push(tm);
            await tm.bootstrapIdentity();

            // Populate cache
            for(let i=0; i<101; i++) {
                // Manually inject to bypass mock caller latency
                tm['stCache'].set(`node-${i}`, await tokenManager.sign({ type: 'ST', sub: 'my-node', aud: `node-${i}` }));
            }
            
            // This should trigger prune
            await tm.getTicketFor('another-target');
            
            expect(tm['stCache'].has('node-0')).toBe(false);
            expect(tm['stCache'].size).toBe(101);
        });

        test('should throw if getting ticket without TGT', async () => {
            const mockCaller = jest.fn();
            const tm = new TicketManager('my-node', tokenManager, mockCaller, mockLogger, keys.privateKey);
            tms.push(tm);
            await expect(tm.getTicketFor('target-node')).rejects.toThrow('No valid TGT available');
        });

        test('should throw on bootstrapIdentity if no private key', async () => {
            const mockCaller = jest.fn();
            const tm = new TicketManager('my-node', tokenManager, mockCaller, mockLogger, undefined);
            tms.push(tm);
            await expect(tm.bootstrapIdentity()).rejects.toThrow('No private key available');
        });

        test('should handle missing tgt or exp gracefully', async () => {
            const mockCaller = jest.fn().mockResolvedValue({ token: null });
            const tm = new TicketManager('my-node', tokenManager, mockCaller, mockLogger, keys.privateKey);
            tms.push(tm);
            await tm.bootstrapIdentity();
            expect(tm.getTGT()).toBeFalsy();
        });
    });

    describe('SecurityManager', () => {
        test('should handle missing secret gracefully', async () => {
            const smEmpty = new SecurityManager();
            await smEmpty.init();
            const data = new Uint8Array([1, 2, 3]);
            expect(await smEmpty.encrypt(data)).toBe(data);
            expect(await smEmpty.decrypt(data)).toBe(data);
        });

        let sm: SecurityManager;
        beforeEach(async () => {
            sm = new SecurityManager('secret');
            await sm.init();
        });

        test('should throw on reused nonce', async () => {
            const data = new Uint8Array([1, 2, 3]);
            const encrypted = await sm.encrypt(data);
            
            await sm.decrypt(encrypted);
            // Re-decrypt should throw due to reused nonce
            await expect(sm.decrypt(encrypted)).rejects.toThrow('Replay detected');
        });

        test('should throw on old timestamp (severe clock skew)', async () => {
            const data = new Uint8Array([1, 2, 3]);
            const encrypted = await sm.encrypt(data);
            
            // Tamper with timestamp or mock Date.now during decrypt?
            // Wait, we can modify the timestamp in the decrypted array before returning?
            // It's authenticated encryption, so we can't easily tamper without failing GCM check.
            // Better to mock Date.now() during encrypt and decrypt.
            const originalNow = Date.now;
            Date.now = jest.fn().mockReturnValue(1000000000000); // T1
            const enc2 = await sm.encrypt(data);
            
            Date.now = jest.fn().mockReturnValue(1000000000000 + 40000); // T2: 40s later (limit is 30s)
            await expect(sm.decrypt(enc2)).rejects.toThrow('Possible replay attack');
            
            Date.now = originalNow;
        });

        test('cleanupNonceCache should remove old nonces', async () => {
            const originalNow = Date.now;
            
            Date.now = jest.fn().mockReturnValue(1000000000000);
            const enc = await sm.encrypt(new Uint8Array([1]));
            await sm.decrypt(enc);
            
            expect(sm['nonceCache'].size).toBe(1);

            Date.now = jest.fn().mockReturnValue(1000000000000 + 40000); // > 30s
            sm['cleanupNonceCache']();
            
            expect(sm['nonceCache'].size).toBe(0);

            Date.now = originalNow;
        });
    });

    describe('RBAC', () => {
        test('authorize should throw if check fails', () => {
            const ctx = { meta: { user: { groups: ['user'] } } };
            expect(() => RBAC.authorize(ctx, { roles: ['admin'] })).toThrow('Unauthorized');
        });

        test('authorize should not throw if check succeeds', () => {
            const ctx = { meta: { user: { groups: ['admin'] } } };
            expect(() => RBAC.authorize(ctx, { roles: ['admin'] })).not.toThrow();
        });

        test('check should return true if no required roles', () => {
            expect(RBAC.check({} as any, { roles: [] })).toBe(true);
        });

        test('check should handle missing user roles', () => {
            expect(RBAC.check({}, { roles: ['admin'] })).toBe(false);
            expect(RBAC.check({ meta: {} } as any, { roles: ['admin'] })).toBe(false);
        });
    });

    describe('IsomorphicCrypto', () => {
        test('verifyEd25519 should return false on malformed signature', async () => {
            const res = await IsomorphicCrypto.verifyEd25519('invalid-base64-!!!', 'payload', keys.publicKey);
            expect(res).toBe(false);
        });
        
        test('methods should work with Uint8Array data', async () => {
            const data = new Uint8Array([1, 2, 3]);
            const hash = await IsomorphicCrypto.sha256(data);
            expect(hash).toBeDefined();

            const sig = await IsomorphicCrypto.signEd25519(data, keys.privateKey);
            const isValid = await IsomorphicCrypto.verifyEd25519(sig, data, keys.publicKey);
            expect(isValid).toBe(true);
        });

        test('should throw if WebCrypto is missing', async () => {
            const originalCrypto = (globalThis as any).crypto;
            (globalThis as any).crypto = undefined;
            IsomorphicCrypto['crypto'] = null;
            
            await expect(IsomorphicCrypto.sha256('test')).rejects.toThrow('WebCrypto not available');
            await expect(IsomorphicCrypto.signEd25519('test', keys.privateKey)).rejects.toThrow('WebCrypto not available');
            await expect(IsomorphicCrypto.verifyEd25519('sig', 'test', keys.publicKey)).rejects.toThrow('WebCrypto not available');
            
            const id = IsomorphicCrypto.randomID(16);
            expect(id.length).toBe(16);
            
            (globalThis as any).crypto = originalCrypto;
            IsomorphicCrypto['crypto'] = originalCrypto;
        });
    });

    describe('MeshTokenManager', () => {
        test('decode should return null on invalid token format', () => {
            const tm = new MeshTokenManager('kdc', keys);
            expect(tm.decode('not-a-token')).toBeNull();
        });

        test('sign should throw if missing privateKey', async () => {
            const tm = new MeshTokenManager('kdc', { publicKey: keys.publicKey });
            await expect(tm.sign({ type: 'TGT', sub: 'node' } as any)).rejects.toThrow('No private key available');
        });

        test('verify should fail if missing publicKey', async () => {
            const tmEmpty = new MeshTokenManager('kdc', { privateKey: keys.privateKey });
            const token = await tmEmpty.sign({ type: 'TGT', sub: 'node' } as any);
            const result = await tmEmpty.verify(token);
            expect(result).toBeNull();
        });

        test('verify should fail if expired', async () => {
            const tm = new MeshTokenManager('kdc', keys);
            const token = await tm.sign({ type: 'TGT', sub: 'node' } as any, -100);
            const result = await tm.verify(token);
            expect(result).toBeNull();
        });
    });
});