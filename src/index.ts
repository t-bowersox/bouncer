import crypto, { KeyObject } from "crypto";
export class Bouncer {
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  constructor(
    private tokenStore: TokenStore,
    privateKey: string,
    publicKey: string,
    passphrase?: string
  ) {
    this.privateKey = passphrase
      ? crypto.createPrivateKey({ key: privateKey, passphrase })
      : crypto.createPrivateKey(privateKey);
    this.publicKey = crypto.createPublicKey(publicKey);
  }
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

export interface ParsedToken {
  token: Base64String;
  signature: Base64String;
}

export type Base64String = string;
