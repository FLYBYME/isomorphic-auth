import { IdentityService } from '../src/core/identity.service';
import { DistributedLedger } from 'raft-consensus';
import { IsomorphicCrypto } from '../src/utils/crypto';
import { ILogger, IStorageAdapter } from '../src/types/auth.types';

jest.mock('raft-consensus', () => ({
    DistributedLedger: jest.fn().mockImplementation(() => ({
        append: jest.fn().mockResolvedValue({ txID: 'mock-tx' })
    }))
}));

describe('IdentityService', () => {
    let identityService: IdentityService;
    let mockStorage: jest.Mocked<IStorageAdapter>;
    let mockLogger: jest.Mocked<ILogger>;

    beforeEach(() => {
        mockStorage = {
            getNode: jest.fn(),
            setNode: jest.fn(),
            deleteNode: jest.fn(),
            get: jest.fn(),
            all: jest.fn(),
            run: jest.fn()
        } as any;
        mockLogger = {
            debug: jest.fn(),
            info: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
            child: jest.fn().mockReturnThis()
        } as any;
        identityService = new IdentityService(mockStorage, mockLogger);
    });

    test('should register a new user', async () => {
        await identityService.created();
        const params = {
            email: 'test@example.com',
            password: 'password123',
            metadata: { name: 'Test User' }
        };
        const ctx = { params, nodeID: 'node-1' } as any;

        const result = await identityService.register(ctx);

        expect(result.email).toBe(params.email);
        expect(result.id).toBeDefined();
        expect(mockLogger.info).toHaveBeenCalledWith(expect.stringContaining('User registered'));
    });

    test('should login a user successfully', async () => {
        await identityService.created();
        const password = 'password123';
        const { hash, salt } = await IsomorphicCrypto.hashPassword(password);
        const userPayload = {
            id: 'user-123',
            email: 'test@example.com',
            hash: `${salt}:${hash}`,
            status: 'ACTIVE'
        };

        mockStorage.get.mockResolvedValue({
            payload: JSON.stringify(userPayload)
        });

        const ctx = {
            params: { email: 'test@example.com', password },
            call: jest.fn().mockResolvedValue({ token: 'mock-tgt' })
        } as any;

        const result = await identityService.login(ctx);

        expect(result.id).toBe(userPayload.id);
        expect(result.token).toBe('mock-tgt');
        expect(ctx.call).toHaveBeenCalledWith('sys.kdc.authenticate', expect.any(Object));
    });

    test('should fail login with wrong password', async () => {
        await identityService.created();
        const { hash, salt } = await IsomorphicCrypto.hashPassword('correct-password');
        mockStorage.get.mockResolvedValue({
            payload: JSON.stringify({
                email: 'test@example.com',
                hash: `${salt}:${hash}`,
                status: 'ACTIVE'
            })
        });

        const ctx = {
            params: { email: 'test@example.com', password: 'wrong-password' }
        } as any;

        await expect(identityService.login(ctx)).rejects.toThrow('Invalid credentials');
    });
});
