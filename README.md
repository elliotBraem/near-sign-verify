# near-sign-verify

Creates and validates NEAR signatures for API authentication.

```bash
npm install near-sign-verify
```

## with KeyPair

Works with both full access and function call access keys.

```typescript
// --- Create request with signed token ---
import { sign } from "near-sign-verify";
import { KeyPair } from '@near-js/crypto';

const keyPair = KeyPair.fromRandom('ed25519'); // for example

const authToken = await sign({
  signer: keyPair.toString(),
  accountId: "you.near", // PubKey owner (you can pretend)
  recipient: "your-service.near",
  data: { customInfo: "login attempt" } // whatever data you wanna pass
});

// --- Send request with the token ---

fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});

// --- Verify the token ---

try {
  const result = await verify(authToken, {
    expectedRecipient: "your-service.near", // Ensure token is for your service
    requireFullAccessKey: false,  // Allow Function Call Access Keys
    nonceMaxAge: 300000,          // 5 minutes since message signed
  });

  // If verification is successful, you get a VerificationResult
  console.log('Successfully verified for account:', result.accountId);
  // you.near
  console.log('Message from token:', result.message);
  // { customInfo: 'login attempt' }

} catch (error: any) {
  // If verification fails, an error is thrown
  console.error('Token verification failed:', error.message);
}
```

## with Wallet

```typescript
import { sign, verify } from 'near-sign-verify';

// use your wallet, wherever it comes from...
const wallet = near // fastnear-js or fastintear
const wallet = await (await this.selector).wallet(); // near-wallet-selector
const { wallet } = useWalletSelector();

const authToken = await sign({
  signer: wallet, // has a signMessage function
  recipient: 'app.near',
  data: { ... }
});

// --- Send request with the token ---

fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});

// --- Verify the token ---

try {
  const result = await verify(authToken, {
    expectedRecipient: "your-service.near", // Ensure token is for your service
    // by default, wallet ensures a full access key (will always work)
    nonceMaxAge: 300000,                    // 5 minutes since message signed
  });

  // If verification is successful, you get a VerificationResult
  console.log('Successfully verified for account:', result.accountId);
  // you.near
  console.log('Message from token:', result.message);
  // { customInfo: 'login attempt' }

} catch (error: any) {
  // If verification fails, an error is thrown
  console.error('Token verification failed:', error.message);
}
```

## with custom nonce + validation

You can override the default nonce generation and validation (timestamp based, maxAge):

```typescript
import { sign, verify } from "near-sign-verify";

const authToken = await sign({
  signer: wallet,
  recipient: "your-service.near",
  nonce: 1, // your nonce override
  data: { customInfo: "login attempt" } // whatever data you wanna pass
})

try {
  const result = await verify(authToken, {
    expectedRecipient: "your-service.near",
    validateNonce: (nonce: Uint8Array): boolean => {
      // do something
      return true;
    }
  });
} catch {
  // failed
}
```

## debugging

You can use the `parseAuthToken` helper method to inspect the outcome of `sign`.

```typescript

import { parseAuthToken, type NearAuthData } from "near-sign-verify";

const authData: NearAuthData = parseAuthToken(authToken);
```
