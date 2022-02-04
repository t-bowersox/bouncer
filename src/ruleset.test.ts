import { Ruleset } from ".";

describe("Ruleset", () => {
  let ruleset: Ruleset;
  const syncRule = (user: object) => user["role"] === "admin";
  const asyncRule = (user: object) =>
    Promise.resolve(user["role"] === "regular");

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
});
