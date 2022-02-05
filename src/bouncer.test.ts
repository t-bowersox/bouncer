import { Bouncer, BouncerError, Ruleset, Token } from "./index";
import { jest } from "@jest/globals";
import * as crypto from "crypto";
import { Base64 } from "@t-bowersox/base64";

jest.mock("crypto");

describe("Bouncer", () => {
  const uuid = "1234-5678-9123-4567";
  const cryptoMock = jest.mocked(crypto, true);
  const storeTokenData = jest.fn<Promise<boolean>, [string, number, number]>();
  const isOnDenyList = jest.fn<Promise<boolean>, [string]>();
  const addToDenyList = jest.fn<Promise<boolean>, [string, number]>();
  let bouncer: Bouncer;

  beforeEach(() => {
    const tokenStore = {
      storeTokenData,
      addToDenyList,
      isOnDenyList,
    };
    bouncer = new Bouncer(tokenStore, "privatePem", "publicPem");
  });

  describe("#createToken", () => {
    test("should return a signed base64 encoded token", async () => {
      const expirationDate = "2022-02-02 20:00:00";
      const expectedToken = {
        sessionId: uuid,
        userId: 1,
        expirationTime: new Date(expirationDate).getTime(),
      };
      storeTokenData.mockResolvedValue(true);
      const jsonToken = JSON.stringify(expectedToken);
      cryptoMock.randomUUID.mockReturnValue(uuid);
      //@ts-expect-error Jest mock
      cryptoMock.createSign.mockImplementation(() => {
        return {
          update: jest.fn().mockReturnThis(),
          end: jest.fn().mockReturnThis(),
          sign: jest.fn().mockReturnValue("signature"),
        };
      });

      expect(await bouncer.createToken(1, new Date(expirationDate))).toBe(
        `${Base64.encode(jsonToken)}.signature`
      );
    });

    test("should throw #BouncerError if unable to save token", async () => {
      const expirationDate = "2022-02-02 20:00:00";
      cryptoMock.randomUUID.mockReturnValue(uuid);
      storeTokenData.mockResolvedValue(false);

      const errorCondition = async () => {
        return bouncer.createToken(1, new Date(expirationDate));
      };

      await expect(errorCondition()).rejects.toThrowError(BouncerError);
    });
  });

  describe("#revokeToken", () => {
    const token: Token = {
      sessionId: uuid,
      userId: 1,
      expirationTime: Date.now(),
    };
    const tokenStr = `${Base64.encode(JSON.stringify(token))}.signature`;

    test("should return true if token is added to the Deny List", async () => {
      addToDenyList.mockResolvedValue(true);
      expect(await bouncer.revokeToken(tokenStr)).toBe(true);
    });

    test("should return false if token is not added to the Deny List", async () => {
      addToDenyList.mockResolvedValue(false);
      expect(await bouncer.revokeToken(tokenStr)).toBe(false);
    });

    test("should return false if passed an empty token", async () => {
      expect(await bouncer.revokeToken("")).toBe(false);
    });
  });

  describe("#validateToken", () => {
    test("should return false if unparsed token is empty string", async () => {
      expect(await bouncer.validateToken("")).toBe(false);
    });

    test("should return false if token signature is not verified", async () => {
      //@ts-expect-error Jest mock
      cryptoMock.createVerify.mockImplementation(() => {
        return {
          update: jest.fn().mockReturnThis(),
          end: jest.fn().mockReturnThis(),
          verify: jest.fn().mockReturnValue(false),
        };
      });

      expect(await bouncer.validateToken("unparsed-token")).toBe(false);
    });

    test("should return false if token has expired", async () => {
      const expirationDate = "2022-01-01 00:00:00";
      const expectedToken = {
        sessionId: uuid,
        userId: 1,
        expirationTime: new Date(expirationDate).getTime(),
      };
      const jsonToken = JSON.stringify(expectedToken);
      const unparsedToken = `${Base64.encode(jsonToken)}.signature`;

      //@ts-expect-error Jest mock
      cryptoMock.createVerify.mockImplementation(() => {
        return {
          update: jest.fn().mockReturnThis(),
          end: jest.fn().mockReturnThis(),
          verify: jest.fn().mockReturnValue(true),
        };
      });

      expect(await bouncer.validateToken(unparsedToken)).toBe(false);
    });

    test("should return false if token is on the Deny List", async () => {
      const expirationDate = Date.now() + 604800000; // 7d in ms
      const expectedToken = {
        sessionId: uuid,
        userId: 1,
        expirationTime: new Date(expirationDate).getTime(),
      };
      const jsonToken = JSON.stringify(expectedToken);
      const unparsedToken = `${Base64.encode(jsonToken)}.signature`;

      //@ts-expect-error Jest mock
      cryptoMock.createVerify.mockImplementation(() => {
        return {
          update: jest.fn().mockReturnThis(),
          end: jest.fn().mockReturnThis(),
          verify: jest.fn().mockReturnValue(true),
        };
      });

      isOnDenyList.mockResolvedValue(true);

      expect(await bouncer.validateToken(unparsedToken)).toBe(false);
    });

    test("should return true if token is not on the Deny List", async () => {
      const expirationDate = Date.now() + 604800000; // 7d in ms
      const expectedToken = {
        sessionId: uuid,
        userId: 1,
        expirationTime: new Date(expirationDate).getTime(),
      };
      const jsonToken = JSON.stringify(expectedToken);
      const unparsedToken = `${Base64.encode(jsonToken)}.signature`;

      //@ts-expect-error Jest mock
      cryptoMock.createVerify.mockImplementation(() => {
        return {
          update: jest.fn().mockReturnThis(),
          end: jest.fn().mockReturnThis(),
          verify: jest.fn().mockReturnValue(true),
        };
      });

      isOnDenyList.mockResolvedValue(false);

      expect(await bouncer.validateToken(unparsedToken)).toBe(true);
    });
  });

  describe("#validateUser", () => {
    const user = {
      id: 1,
      role: "regular",
      permissions: { read: true, write: false },
    };
    const syncRuleTrue = (user: object) => user["permissions"]["read"] === true;
    const syncRuleFalse = (user: object) => user["role"] === "admin";
    const asyncRuleTrue = async (user: object) => {
      return Promise.resolve(user["permissions"]["read"] === true);
    };
    const asyncRuleFalse = async (user: object) => {
      return Promise.resolve(user["role"] === "admin");
    };
    let ruleset: Ruleset;

    beforeEach(() => {
      ruleset = new Ruleset();
    });

    test("returns false if a sync rule returns false", async () => {
      ruleset.addSyncRule(syncRuleTrue).addSyncRule(syncRuleFalse);
      expect(await bouncer.validateUser(user, ruleset)).toBe(false);
    });

    test("returns false if an async rule returns false", async () => {
      ruleset
        .addSyncRule(syncRuleTrue)
        .addAsyncRule(asyncRuleTrue)
        .addAsyncRule(asyncRuleFalse);
      expect(await bouncer.validateUser(user, ruleset)).toBe(false);
    });

    test("returns true if sync & async rules return true", async () => {
      ruleset.addSyncRule(syncRuleTrue).addAsyncRule(asyncRuleTrue);
      expect(await bouncer.validateUser(user, ruleset)).toBe(true);
    });

    test("returns true if no async rules & sync rules return true", async () => {
      ruleset.addSyncRule(syncRuleTrue);
      expect(await bouncer.validateUser(user, ruleset)).toBe(true);
    });

    test("returns true if no sync rules & async rules return true", async () => {
      ruleset.addAsyncRule(asyncRuleTrue);
      expect(await bouncer.validateUser(user, ruleset)).toBe(true);
    });
  });
});
