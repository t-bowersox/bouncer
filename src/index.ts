export class Bouncer {
  constructor(
    private privateKey: string,
    private publicKey: string,
    private tokenStore: TokenStore
  ) {}
}

export interface TokenStore {
  addToDenyList(sessionId: string, timestamp: number): boolean;
  isOnDenyList(sessionId: string): boolean;
}

export interface Token {
  sessionId: string;
  userId: string | number;
  expirationTime: number;
}

export type Base64String = string;
