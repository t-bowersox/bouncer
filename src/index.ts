import crypto, { KeyObject } from "crypto";
import { Base64 } from "@t-bowersox/base64";

const ALGORITHM = "sha256";
const SIGNATURE_ENCODING = "base64";

export class Bouncer {
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  constructor(
    private tokenStore: TokenStore,
    privatePem: string,
    publicPem: string,
    passphrase?: string
  ) {
    this.privateKey = passphrase
      ? crypto.createPrivateKey({ key: privatePem, passphrase })
      : crypto.createPrivateKey(privatePem);
    this.publicKey = crypto.createPublicKey(publicPem);
  }

  createToken(userId: string | number, expirationDate: Date): string {
    const sessionId = this.generateSessionId();
    const expirationTime = expirationDate.getTime();
    const token: Token = {
      sessionId,
      userId,
      expirationTime,
    };
    const encodedToken = this.encodeToken(token);
    const signature = this.signToken(encodedToken);
    return `${encodedToken}.${signature}`;
  }

  revokeToken(sessionId: string): boolean {
    return this.tokenStore.addToDenyList(sessionId, Date.now());
  }

  validateToken(unparsedToken: Base64String): boolean {
    if (!unparsedToken) {
      return false;
    }
    const { token, signature } = this.parseToken(unparsedToken);
    const verified = this.verifyToken(token, signature);
    if (!verified) {
      return false;
    }
    const decodedToken = this.decodeToken(token);
    if (decodedToken.expirationTime < Date.now()) {
      return false;
    }
    const denied = this.tokenStore.isOnDenyList(decodedToken.sessionId);
    return !denied;
  }

  async validateUser(user: object, rules: Ruleset): Promise<boolean> {
    return rules.evaluateSync(user) && (await rules.evaluateAsync(user));
  }

  private verifyToken(token: Base64String, signature: Base64String): boolean {
    const verifier = crypto.createVerify(ALGORITHM);
    return verifier
      .update(token)
      .end()
      .verify(this.publicKey, signature, SIGNATURE_ENCODING);
  }

  private generateSessionId(): string {
    return crypto.randomUUID();
  }

  private encodeToken(token: Token): Base64String {
    const tokenJson = JSON.stringify(token);
    return Base64.encode(tokenJson);
  }

  private decodeToken(encodedToken: Base64String): Token {
    const tokenJson = Base64.decode(encodedToken);
    return JSON.parse(tokenJson);
  }

  private signToken(encodedToken: Base64String): Base64String {
    const signer = crypto.createSign(ALGORITHM);
    return signer
      .update(encodedToken)
      .end()
      .sign(this.privateKey, SIGNATURE_ENCODING);
  }

  private parseToken(encodedToken: Base64String): ParsedToken {
    const splitToken: Base64String[] = encodedToken.split(".");
    return {
      token: splitToken[0],
      signature: splitToken[1],
    };
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
