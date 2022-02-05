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

  /**
   * Creates a new access token.
   * @param userId The unique ID for a user.
   * @param expirationDate The date the token should expire.
   * @returns A dot-separated string containing the base64-encoded token and its base64-encoded signature.
   */
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

  /**
   * Adds a token to the `TokenStore`'s Deny List.
   * @param unparsedToken The base64-encoded string returned by `createToken`.
   * @returns `true` if the token was successfully added to the Deny List, `false` if not.
   */
  revokeToken(unparsedToken: string): boolean {
    if (!unparsedToken) {
      return false;
    }
    const { token } = this.parseToken(unparsedToken);
    const decodedToken = this.decodeToken(token);
    return this.tokenStore.addToDenyList(decodedToken.sessionId, Date.now());
  }

  /**
   * Evaluates it a token is valid based on its signature, expiration date, and Deny List status.
   * @param unparsedToken The string returned from `createToken`.
   * @returns `true` if the token is valid, `false` if not.
   */
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

  /**
   * Evaluates a user's attributes against a `RuleSet` to determine if the user meets the criteria for access.
   * @param userData The data to be evaluated by the `RuleSet`.
   * @param rules A `RuleSet` instance containing one or more `ValidationRule` and/or `AsyncValidationRule` functions.
   * @returns A promise resolving to `true` if all rules in the set returned `true`, otherwise `false`.
   */
  async validateUser<T>(userData: T, rules: Ruleset): Promise<boolean> {
    return (
      rules.evaluateSync(userData) && (await rules.evaluateAsync(userData))
    );
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

export class BouncerError extends Error {
  name = "BouncerError";
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

export class Ruleset {
  private syncRules: Set<ValidationRule>;
  private asyncRules: Set<AsyncValidationRule>;

  constructor(
    syncRules?: ValidationRule[],
    asyncRules?: AsyncValidationRule[]
  ) {
    this.syncRules = new Set(syncRules);
    this.asyncRules = new Set(asyncRules);
  }

  /**
   * Adds a synchronous `ValidationRule` to the `RuleSet`.
   * @param rule The `ValidationRule` to add.
   * @returns The `RuleSet` instance so you can chain multiple calls.
   */
  addSyncRule(rule: ValidationRule): Ruleset {
    this.syncRules.add(rule);
    return this;
  }

  /**
   * Adds an `AsyncValidationRule` to the `RuleSet`.
   * @param rule The `AsyncValidationRule` to add.
   * @returns The `RuleSet` instance so you can chain multiple calls.
   */
  addAsyncRule(rule: AsyncValidationRule): Ruleset {
    this.asyncRules.add(rule);
    return this;
  }

  /**
   * Checks if the `RuleSet` contains a specific `ValidationRule`.
   * @param rule The rule to look for.
   * @returns `true` if present in the `RuleSet`, otherwise `false`.
   */
  hasSyncRule(rule: ValidationRule): boolean {
    return this.syncRules.has(rule);
  }

  /**
   * Checks if the `RuleSet` contains a specific `AsyncValidationRule`.
   * @param rule The rule to look for.
   * @returns `true` if present in the `RuleSet`, otherwise `false`.
   */
  hasAsyncRule(rule: AsyncValidationRule): boolean {
    return this.asyncRules.has(rule);
  }

  /**
   * Deletes a `ValidationRule` from the `RuleSet`.
   * @param rule The rule to delete.
   * @returns `true` if value was in the set, `false` if not.
   */
  deleteSyncRule(rule: ValidationRule): boolean {
    return this.syncRules.delete(rule);
  }

  /**
   * Deletes an `AsyncValidationRule` from the `RuleSet`.
   * @param rule The rule to delete.
   * @returns `true` if value was in the set, `false` if not.
   */
  deleteAsyncRule(rule: AsyncValidationRule): boolean {
    return this.asyncRules.delete(rule);
  }

  /**
   * Deletes all `ValidationRule`s from the `RuleSet`.
   */
  clearSyncRules(): void {
    return this.syncRules.clear();
  }

  /**
   * Deletes all `AsyncValidationRule`s from the `RuleSet`.
   */
  clearAsyncRules(): void {
    return this.asyncRules.clear();
  }

  /**
   * Compares user data against the `RuleSet`'s internal set of `ValidationRule`s.
   * This normally should not be called directly.
   * Instead, use `Bouncer`'s `validateUser` method.
   * @param userData The data to evaluate in the `ValidationRule` functions.
   * @returns `true` if all `ValidationRule`s returned true, otherwise `false`.
   */
  evaluateSync<T>(userData: T): boolean {
    for (const rule of this.syncRules) {
      if (!rule(userData)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Compares user data against the `RuleSet`'s internal set of `AsyncValidationRule`s.
   * This normally should not be called directly.
   * Instead, use `Bouncer`'s `validateUser` method.
   * @param userData The data to evaluate in the `ValidationRule` functions.
   * @returns A promise resolving to `true` if all `AsyncValidationRule`s returned true,
   * otherwise `false`.
   */
  async evaluateAsync<T>(userData: T): Promise<boolean> {
    for (const rule of this.asyncRules) {
      const result = await rule(userData);
      if (!result) {
        return false;
      }
    }
    return true;
  }
}

export type ValidationRule<T = any> = (userData: T) => boolean;

export type AsyncValidationRule<T = any> = (userData: T) => Promise<boolean>;
