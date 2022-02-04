import { Ruleset } from ".";

describe("Ruleset", () => {
  let ruleset: Ruleset;
  const syncRule = (user: object) => user["role"] === "admin";
  const asyncRule = (user: object) =>
    Promise.resolve(user["role"] === "regular");
  const user = {
    id: 1,
    role: "regular",
    permissions: { read: true, write: false },
  };

  beforeEach(() => {
    const initialSyncFn = () => true;
    const initialAsyncFn = () => Promise.resolve(true);
    ruleset = new Ruleset([initialSyncFn], [initialAsyncFn]);
  });

  test("should add sync rules", () => {
    ruleset.addSyncRule(syncRule);
    expect(ruleset.hasSyncRule(syncRule)).toBe(true);
  });

  test("should add async rules", () => {
    ruleset.addAsyncRule(asyncRule);
    expect(ruleset.hasAsyncRule(asyncRule)).toBe(true);
  });

  test("should delete sync rules", () => {
    ruleset.addSyncRule(syncRule).deleteSyncRule(syncRule);
    expect(ruleset.hasSyncRule(syncRule)).toBe(false);
  });

  test("should delete async rules", () => {
    ruleset.addAsyncRule(asyncRule).deleteAsyncRule(asyncRule);
    expect(ruleset.hasAsyncRule(asyncRule)).toBe(false);
  });

  test("should clear sync rules", () => {
    ruleset.addSyncRule(syncRule).clearSyncRules();
    expect(ruleset.hasSyncRule(syncRule)).toBe(false);
  });

  test("should clear async rules", () => {
    ruleset.addAsyncRule(asyncRule).clearAsyncRules();
    expect(ruleset.hasAsyncRule(asyncRule)).toBe(false);
  });

  describe("#evaluateSync", () => {
    const syncRuleTrue = (user: object) => user["permissions"]["read"] === true;
    const syncRuleFalse = (user: object) => user["role"] === "admin";

    beforeEach(() => {
      ruleset.clearSyncRules();
    });

    test("returns false if a sync function returns false", () => {
      ruleset.addSyncRule(syncRuleTrue).addSyncRule(syncRuleFalse);
      expect(ruleset.evaluateSync(user)).toBe(false);
    });

    test("returns true if all sync functions return true", () => {
      ruleset.addSyncRule(syncRuleTrue).addSyncRule(syncRuleTrue);
      expect(ruleset.evaluateSync(user)).toBe(true);
    });
  });

  describe("#evaluateAsync", () => {
    const asyncRuleTrue = async (user: object) => {
      return Promise.resolve(user["permissions"]["read"] === true);
    };
    const asyncRuleFalse = async (user: object) => {
      return Promise.resolve(user["role"] === "admin");
    };

    test("returns false if an async function returns false", async () => {
      ruleset.addAsyncRule(asyncRuleTrue).addAsyncRule(asyncRuleFalse);
      expect(await ruleset.evaluateAsync(user)).toBe(false);
    });

    test("returns true if all async functions return true", async () => {
      ruleset.addAsyncRule(asyncRuleTrue).addAsyncRule(asyncRuleTrue);
      expect(await ruleset.evaluateAsync(user)).toBe(true);
    });
  });
});
