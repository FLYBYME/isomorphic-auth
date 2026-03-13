import { TokenPayload, NodeRecord } from './auth.schema';

export interface ILogger {
    debug(msg: string, data?: Record<string, unknown>): void;
    info(msg: string, data?: Record<string, unknown>): void;
    warn(msg: string, data?: Record<string, unknown>): void;
    error(msg: string, data?: Record<string, unknown>): void;
    child(context: Record<string, unknown>): ILogger;
}

export interface IStorageAdapter {
    get(key: string): Promise<NodeRecord | null>;
    set(key: string, value: NodeRecord): Promise<void>;
    delete(key: string): Promise<void>;
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
