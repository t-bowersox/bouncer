# bouncer

A tool for checking user authorization.

## Installation

```bash
npm i @t-bowersox/bouncer
```

## Usage

Bouncer performs two primary sets of tasks:

- Issuing, revoking, & validating signed access tokens.
- Validating a user's attributes against a permissions ruleset.

### Requirements

In order to create a `Bouncer` instance, you must have the following:

- A private key string in PEM format.
- If your private key is encrypted by a passphrase, you must provide it as well.
- A public key string in PEM format.
- An object that implements the `TokenStore` interface.

Need help generating keys? [This article](https://www.scottbrady91.com/openssl/creating-rsa-keys-using-openssl) provides
a good explainer using OpenSSL.

#### Token signing

The private and public keys are necessary for signing and verifying access tokens. Under the hood, Bouncer uses the
Node.js [`crypto.createPrivateKey`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptocreateprivatekeykey)
and [`crypto.createPublicKey`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptocreatepublickeykey)
methods to create a `KeyObject` for each.

Those `KeyObject`s are used with instances of
Node's [`Sign`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#class-sign)
and [`Verify`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#class-verify) classes when signing and
verifying access tokens, respectively. The algorithm used for signatures is SHA256.

The `Token` interface stores only a unique session ID, the user's ID, and an expiration timestamp. The session ID is
generated using
Node's [`crypto.randomUUID`](https://nodejs.org/dist/latest-v16.x/docs/api/crypto.html#cryptorandomuuidoptions), which
uses a cryptographic pseudorandom number generator.

#### Token stores

The `TokenStore` interface requires an object to have two methods that are used for tracking revoked tokens:

- `addToDenyList` - This is called by Bouncer to add a session ID to the "Deny List", which is a list of revoked tokens.
- `isOnDenyList` - This is called by Bouncer during token validation to see if a session ID has been revoked.

It is up to you to handle where to store the data, whether it's a key-value store, relational database, etc.

If you want to keep a dataset or log of all tokens issued by Bouncer, you will need to handle that yourself since it's
outside the scope of what Bouncer's purpose.

### Authorization flow

#### Creating a `Bouncer` instance

```typescript
import { Bouncer } from "@t-bowersox/bouncer";

// This TokenStore implementation is just for demonstration
const tokenStore = {
  addToDenyList(sessionId: string, timestamp: number): boolean {
    const database = new SomeDatabaseClass();
    return database.insert(sessionId, timestamp);
  },

  isOnDenyList(sessionId: string): boolean {
    const database = new SomeDatabaseClass();
    return database.get(sessionId);
  },
};

// You'll most likely want to use env variables for the keys & passphrase
const bouncer = new Bouncer(
  tokenStore,
  "my-private-key-pem",
  "my-public-key-pem",
  "my-private-key-passphrase"
);
```

#### Creating an access token

An access token is a dot-separated string that includes:

- The base64 encoded token.
- The base64 encoded signature for that token.

For example: `<base64-encoded-token>.<base64-encoded-signature>`. Being base64 encoded, it's suitable for returning to
the user in a secure, HTTP-only cookie.

To create a token, pass the user's ID and an expiration date (as a `Date` object) to the `createToken` method.

```typescript
const token = bouncer.createToken(1, new Date("2022-02-28 00:00:00"));
```

#### Revoking an access token

In cases where you need to invalidate a session ID, you can call the `revokeToken` method. This will add the session ID
to Bouncer's Deny List, which is a store of all revoked tokens. Bouncer checks this list during the token validation
process.

To add a token to the Deny List, pass it to `revokeToken`. It will return `true` if it was successful, `false` if not.

```typescript
const revoked = bouncer.revokeToken(
  "<base64-encoded-token>.<base64-encoded-signature>"
);
```

#### Validating a token

To validate a token, simply pass it to the `validateToken` method. Bouncer will return a boolean response based on the
following criteria:

1. Is the token's signature verified? If so, then check:
2. Has the token expired? If not, then check:
3. Is the token on the Deny List? If not, return `true`.

Otherwise, Bouncer returns `false` indicating the token is invalid. That's a signal to your app to deny access to that
user.

```typescript
const validated = bouncer.validateToken(
  "<base64-encoded-token>.<base64-encoded-signature>"
);
```

#### Validating a user

Bouncer's `validateUser` method allows you to compare a user's attributes to a `RuleSet` of validator functions. Each of
the functions you add to a `RuleSet` take a value and, based on your criteria, returns a boolean: `true` if
validated, `false` if not.

Each `RuleSet` keeps two internal sets of functions: one for synchronous functions and the other for async functions.
All functions in the sets must return true in order for Bouncer's `validateUser` method to return `true`. If just one
returns `false`, then so will `validateUser`.

```typescript
type ValidationRule<T = any> = (userData: T) => boolean;
type AsyncValidationRule<T = any> = (userData: T) => Promise<boolean>;
```

To avoid unnecessary async calls, Bouncer will first evaluate the synchronous validators if present. Only if all of
those return `true` will it proceed to the async validators.

You can create as many instances of the `RuleSet` class as you need for your application. For example, you could
have `RuleSet`s for different user types, different application routes, etc.

```typescript
import { Bouncer, RuleSet } from "@t-bowersox/bouncer";
import { User } from "your-app-code";

const user: User = {
  id: 1,
  role: "regular",
  permissions: { read: true, write: false },
};

const syncRuleExample = (user: User): boolean =>
  user["permissions"]["read"] === true;

const asyncRuleExample = async (user: User): Promise<boolean> => {
  const database = new MyDatabaseClass();
  const result = await database.getSomeUserData(user.id);
  return !!result;
};

let ruleSet = new RuleSet([syncRuleExample], [asyncRuleExample]);

// Or...

ruleSet = new RuleSet()
  .addSyncRule(syncRuleExample)
  .addAsyncRule(asyncRuleExample);

// Then...
const bouncer = new Bouncer(/*...*/);
const validUser = await bouncer.validateUser(user, ruleSet);
```

## API

### Class `Bouncer`

Creates a new `Bouncer` instance.

```typescript
class Bouncer {
  constructor(
    tokenStore: TokenStore,
    privatePem: string,
    publicPem: string,
    passphrase?: string
  ) {}
}
```

Parameters:

- `tokenStore`: an object implementing the `TokenStore` interface, used for adding to and checking the Deny List of
  tokens.
- `privatePem`: a string containing a private key in PEM format, used for signing tokens.
- `publicPem`: a string containing the correspondnig public key in PEM format, used for verifying tokens.
- `passphrase`: if the private key was encrypted with a passphrase, pass it to this parameter.

#### Method `createToken`

Creates a new access token.

```typescript
class Bouncer {
  createToken(userId: string | number, expirationDate: Date): string {}
}
```

Parameters:

- `userId`: a string or a number that is the unique ID for your user.
- `expirationDate`: a `Date` object that indicates when the token should expire.

Returns:

- A dot-separated string containing the base64-encoded token and its base64-encoded signature (
  i.e. `<base64-encoded-token>.<base64-encoded-signature>`)

#### Method `revokeToken`

Adds a token to the `TokenStore`'s Deny List.

```typescript
class Bouncer {
  revokeToken(unparsedToken: string): boolean {}
}
```

Parameters:

- `unparsedToken`: the string returned from `createToken`.

Returns:

- `true` if the token was successfully added to the Deny List, `false` if not.

#### Method `validateToken`

Evaluates it a token is valid based on its signature, expiration date, and Deny List status.

```typescript
class Bouncer {
  validateToken(unparsedToken: Base64String): boolean {}
}
```

Parameters:

- `unparsedToken`: the string returned from `createToken`.

Returns:

- `true` if the token is valid, `false` if not.

#### Method `validateUser`

Evaluates a user's attributes against a `RuleSet` to determine if the user meets the criteria for access.

```typescript
class Bouncer {
  validateUser<T>(userData: T, rules: Ruleset): Promise<boolean> {}
}
```

Parameters:

- `userData`: the data to be evaluated by the `RuleSet`.
- `rules`: a `RuleSet` instance containing one or more `ValidationRule` and/or `AsyncValidationRule` functions.

Returns:

- A promise resolving to `true` if all rules in the set returned `true`, otherwise `false`.

### Interface `TokenStore`

Contains methods used by Bouncer to add revoked tokens to a database (referred to as the Deny List), as well as check
for the existance of a token in that database.

```typescript
interface TokenStore {
  addToDenyList(sessionId: string, timestamp: number): boolean;

  isOnDenyList(sessionId: string): boolean;
}
```

#### Method `addToDenyList`

Stores the session ID and timestamp of a token in a database.

```typescript
interface TokenStore {
  addToDenyList(sessionId: string, timestamp: number): boolean;
}
```

Parameters:

- `sessionId` - a string containing the revoked token's session ID.
- `timestamp` - a number containing the current timestamp provided by `Date.now()`.

Returns:

- `true` if the token was successfully saved, `false` if not.

#### Method `isOnDenyList`

Looks for the session ID of a token in a database.

```typescript
interface TokenStore {
  isOnDenyList(sessionId: string): boolean;
}
```

Parameters:

- `sessionId` - a string containing the session ID to look for.

Returns:

- `true` if the token was found, `false` if not.

### Type `Base64String`

Indicates a string has been base64-encoded.

```typescript
type Base64String = string;
```

### Class `RuleSet`

```typescript
class RuleSet {
  constructor(
    syncRules?: ValidationRule[],
    asyncRules?: AsyncValidationRule[]
  ) {}
}
```

Parameters:

- `syncRules`: an optional array of `ValidationRule` functions.
- `asyncRules`: an optional array of `AsyncValidationRule` functions.

#### Method `addSyncRule`

Adds a synchronous `ValidationRule` to the `RuleSet`.

```typescript
class RuleSet {
  addSyncRule(rule: ValidationRule): Ruleset {}
}
```

Parameters:

- `rule`: the `ValidationRule` function to add.

Returns:

- The `RuleSet` instance so you can chain multiple calls.

#### Method `addAsyncRule`

Adds an `AsyncValidationRule` to the `RuleSet`.

```typescript
class Ruleset {
  addAsyncRule(rule: AsyncValidationRule): Ruleset {}
}
```

Parameters:

- `rule`: the `AsyncValidationRule` function to add.

Returns:

- The `RuleSet` instance so you can chain multiple calls.

#### Method `hasSyncRule`

Checks if the `RuleSet` contains a specific `ValidationRule`.

```typescript
class RuleSet {
  hasSyncRule(rule: ValidationRule): boolean {}
}
```

Parameters:

- `rule`: the `ValidationRule` to look for.

Returns:

- `true` if present in the `RuleSet`, otherwise `false`.

#### Method `hasAsyncRule`

Checks if the `RuleSet` contains a specific `AsyncValidationRule`.

```typescript
class RuleSet {
  hasAsyncRule(rule: AsyncValidationRule): boolean {}
}
```

Parameters:

- `rule`: the `AsyncValidationRule` to look for.

Returns:

- `true` if present in the `RuleSet`, otherwise `false`.

#### Method `deleteSyncRule`

Deletes a `ValidationRule` from the `RuleSet`.

```typescript
class RuleSet {
  deleteSyncRule(rule: ValidationRule): boolean {}
}
```

Parameters:

- `rule`: the `ValidationRule` to delete.

Returns:

- `true` if value was in the set, `false` if not.

#### Method `deleteAsyncRule`

Deletes an `AsyncValidationRule` from the `RuleSet`.

```typescript
class RuleSet {
  deleteAsyncRule(rule: AsyncValidationRule): boolean {}
}
```

Parameters:

- `rule`: the `AsyncValidationRule` to delete.

Returns:

- `true` if value was in the set, `false` if not.

#### Method `clearSyncRules`

Deletes all `ValidationRule`s from the `RuleSet`.

```typescript
class RuleSet {
  clearSyncRules(): void {}
}
```

#### Method `clearAsyncRules`

Deletes all `AsyncValidationRule`s from the `RuleSet`.

```typescript
class RuleSet {
  clearAsyncRules(): void {}
}
```

#### Method `evaluateSync`

Compares user data against the `RuleSet`'s internal set of `ValidationRule`s. This normally should not be called
directly. Instead, use `Bouncer`'s `validateUser` method.

```typescript
class RuleSet {
  evaluateSync<T>(userData: T): boolean {}
}
```

Parameters:

- `userData`: the data to evaluate in the `ValidationRule` functions.

Returns:

- `true` if all `ValidationRule`s returned true, otherwise `false`.

#### Method `evaluateAsync`

Compares user data against the `RuleSet`'s internal set of `AsyncValidationRule`s. This normally should not be called
directly. Instead, use `Bouncer`'s `validateUser` method.

```typescript
class RuleSet {
  evaluateAsync<T>(userData: T): Promise<boolean> {}
}
```

Parameters:

- `userData`: the data to evaluate in the `ValidationRule` functions.

Returns:

- A promise resolving to `true` if all `AsyncValidationRule`s returned true, otherwise `false`.

### Type `ValidationRule`

A function that evaluates user data synchronously.

```typescript
type ValidationRule<T = any> = (userData: T) => boolean;
```

Parameters:

- `userData`: the data to evaluate.

Returns:

- `true` if the data passed validation, `false` if not.

### Type `AsyncValidationRule`

A function that evaluates user data asynchronously.

```typescript
type AsyncValidationRule<T = any> = (userData: T) => Promise<boolean>;
```

Parameters:

- `userData`: the data to evaluate.

Returns:

- A promise resolving to `true` if the data passed validation, or `false` if not.

## Contributing

This is primarily a package that I intend to reuse in my own projects. I've decided to open source it in case there are
other folks who might also find it useful.

With that in mind, I only expect to make changes to Container that jibe with how I intend to use it myself.

But if you do have ideas or found bugs, please do file an issue and I'll gladly review it. 🙂
