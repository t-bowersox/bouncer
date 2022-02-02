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
