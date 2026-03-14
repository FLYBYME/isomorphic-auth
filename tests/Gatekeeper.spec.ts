import { Gatekeeper } from '../src/core/Gatekeeper';
import { MeshTokenManager } from '../src/core/MeshTokenManager';
import { IsomorphicCrypto } from '../src/utils/crypto';
import { ILogger } from '../src/types/auth.types';

describe('Gatekeeper', () => {
    let gatekeeper: Gatekeeper;
    let tokenManager: MeshTokenManager;
    let mockLogger: jest.Mocked<ILogger>;
    let keys: { publicKey: string, privateKey: string };

    beforeAll(async () => {
        keys = await IsomorphicCrypto.generateKeyPair();
    });

    beforeEach(() => {
        tokenManager = new MeshTokenManager('test-issuer', keys);
        mockLogger = {
            debug: jest.fn(),
            info: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
            child: jest.fn().mockReturnThis()
        } as any;
        gatekeeper = new Gatekeeper('node-1', tokenManager, mockLogger, keys.publicKey);
    });

    test('should verify a valid service ticket', async () => {
        const ticket = await tokenManager.sign({
            type: 'ST',
            sub: 'node-2',
            aud: 'node-1'
        });

        const payload = await gatekeeper.verifyServiceTicket(ticket);
        expect(payload).toBeDefined();
        expect(payload?.sub).toBe('node-2');
        expect(payload?.aud).toBe('node-1');
    });

    test('should fail if audience mismatch', async () => {
        const ticket = await tokenManager.sign({
            type: 'ST',
            sub: 'node-2',
            aud: 'wrong-node'
        });

        const payload = await gatekeeper.verifyServiceTicket(ticket);
        expect(payload).toBeNull();
        expect(mockLogger.error).toHaveBeenCalledWith(expect.stringContaining('Audience mismatch'));
    });

    test('should fail for invalid signature', async () => {
        const otherKeys = await IsomorphicCrypto.generateKeyPair();
        const otherTokenManager = new MeshTokenManager('other', otherKeys);
        const ticket = await otherTokenManager.sign({
            type: 'ST',
            sub: 'node-2',
            aud: 'node-1'
        });

        const payload = await gatekeeper.verifyServiceTicket(ticket);
        expect(payload).toBeNull();
        expect(mockLogger.warn).toHaveBeenCalledWith(expect.stringContaining('Invalid ticket signature'));
    });

    test('should perform PAC check-back', async () => {
        const mockCaller = jest.fn().mockResolvedValue({ valid: true });
        const result = await gatekeeper.checkPAC('user-1', mockCaller);
        expect(result).toBe(true);
        expect(mockCaller).toHaveBeenCalledWith('sys.kdc.validate_pac', { subjectID: 'user-1' });
    });
});
