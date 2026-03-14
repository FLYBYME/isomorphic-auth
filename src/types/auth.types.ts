import { TokenPayload, NodeRecord } from './auth.schema';

export interface ILogger {
    debug(msg: string, data?: Record<string, unknown>): void;
    info(msg: string, data?: Record<string, unknown>): void;
    warn(msg: string, data?: Record<string, unknown>): void;
    error(msg: string, data?: Record<string, unknown>): void;
    child(context: Record<string, unknown>): ILogger;
}

export interface IStorageAdapter {
    // Key-Value style for NodeRecord
    getNode(key: string): Promise<NodeRecord | null>;
    setNode(key: string, value: NodeRecord): Promise<void>;
    deleteNode(key: string): Promise<void>;
    
    // SQL style for DistributedLedger (must match raft-consensus IStorageAdapter)
    run(sql: string, params?: unknown[]): Promise<any>;
    get<T = unknown>(sql: string, params?: unknown[]): Promise<T | undefined>;
    all<T = unknown>(sql: string, params?: unknown[]): Promise<T[]>;
}

export interface BaseMeshToken {
    iss: string;
    iat?: number;
    exp?: number;
}

export interface TicketGrantingTicketPayload extends BaseMeshToken {
    type: 'TGT';
    sub: string;
    capabilities: string[];
}

export interface ServiceTicketPayload extends BaseMeshToken {
    type: 'ST';
    sub: string;
    aud: string;
    sessionKey?: string;
}
