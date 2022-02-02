export class Bouncer {
  constructor(
    private privateKey: string,
    private publicKey: string,
    private tokenStore: TokenStore
  ) {}
}

