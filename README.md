# near-sign-verify

Creates and validates NEAR signatures for API authentication, with alignment to [NEP-413] for message signing.

```bash
npm install near-sign-verify
```

## Features

*   Sign messages with a KeyPair or a NEP-413 compliant wallet.
*   Verify signed messages with robust options.
*   Support for custom nonce generation and validation.
*   Support for `state` parameter for CSRF protection (NEP-413).
*   Sign any serializable message content (strings, objects, etc.).
*   Flexible recipient validation.
*   Provides NEP-413 core types (`SignMessageParams`, `SignedMessage`, `SignedPayload`) for interoperability.

## with KeyPair

Works with both full access and function call access keys (configurable in `verify` options).

```typescript
// --- Create request with signed token ---
import { sign, verify, type VerificationResult } from "near-sign-verify";
import { KeyPair } from '@near-js/crypto'; // Or your preferred crypto library

const keyPair = KeyPair.fromRandom('ed25519'); // for example

// Example 1: Signing a simple string message
const authTokenString = await sign({
  signer: keyPair.toString(),
  accountId: "you.near", // PubKey owner
  recipient: "your-service.near",
  message: "login attempt",
  state: "client-generated-csrf-token" // Optional state parameter
});

// Example 2: Signing a structured message object
interface MyLoginMessage {
  action: string;
  timestamp: number;
  details?: string;
}

const structuredMessage: MyLoginMessage = {
  action: "authenticateUser",
  timestamp: Date.now(),
  details: "User initiated login via web form"
};

const authTokenObject = await sign<MyLoginMessage>({
  signer: keyPair.toString(),
  accountId: "you.near",
  recipient: "your-service.near",
  message: structuredMessage,
  state: "another-csrf-token",
  // messageSerializer: (msg) => JSON.stringify(msg) // Default for non-string messages
});


// --- Send request with the token ---
fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authTokenString}` }, // or authTokenObject
});

// --- Verify the token ---

// Verifying the string message token
try {
  const result: VerificationResult<string> = await verify(authTokenString, {
    expectedRecipient: "your-service.near", // Ensure token is for your service
    // requireFullAccessKey: true, (default) // Set to false to allow Function Call Access Keys
    nonceMaxAge: 300000,          // 5 minutes since message signed
    expectedState: "client-generated-csrf-token" // Validate the state
  });

  console.log('Successfully verified for account:', result.accountId); // you.near
  console.log('Message from token:', result.message); // "login attempt"
  console.log('State from token:', result.state); // "client-generated-csrf-token"

} catch (error: any) {
  console.error('Token verification failed:', error.message);
}

// Verifying the structured message token
try {
  const resultObj: VerificationResult<MyLoginMessage> = await verify<MyLoginMessage>(authTokenObject, {
    expectedRecipient: "your-service.near",
    nonceMaxAge: 300000,
    expectedState: "another-csrf-token",
    // messageParser: (msgStr) => JSON.parse(msgStr) // Default for non-string messages
  });

  console.log('Successfully verified object message for account:', resultObj.accountId);
  console.log('Parsed Message from token:', resultObj.message.action, resultObj.message.timestamp);
  // "authenticateUser", 167...

} catch (error: any) {
  console.error('Token verification failed:', error.message);
}
```

## with a Wallet (NEP-413 Compliant)

Uses a wallet object that implements the `WalletInterface` (which expects `signMessage` to conform to NEP-413 `SignMessageParams` and `SignedMessage`).

```typescript
import { sign, verify, type WalletInterface, type SignMessageParams, type SignedMessage, type VerificationResult } from 'near-sign-verify';

// Assume 'wallet' is an object implementing WalletInterface
// const wallet: WalletInterface = ...;

const authToken = await sign({
  signer: wallet, // Wallet object
  recipient: 'app.near',
  message: "user action confirmation",
  state: "wallet-session-state"
});

// --- Send request with the token ---
// ... (same as above)

// --- Verify the token ---
try {
  const result: VerificationResult = await verify(authToken, {
    expectedRecipient: "app.near",
    // requireFullAccessKey: true, // Default
    nonceMaxAge: 300000,
    expectedState: "wallet-session-state",
    // Example of custom recipient validation
    validateRecipient: (receivedRecipient) => {
      const allowedRecipients = ["app.near", "staging.app.near"];
      return allowedRecipients.includes(receivedRecipient);
    }
  });

  console.log('Successfully verified with wallet for account:', result.accountId);
  console.log('Message:', result.message);

} catch (error: any) {
  console.error('Token verification failed:', error.message);
}
```

## Custom Nonce and Validation

You can override the default nonce generation (timestamp-based) and validation.

```typescript
import { sign, verify, generateNonce } from "near-sign-verify";

// Example: Using a custom Uint8Array nonce
const customNonce = generateNonce(); // Or your own 32-byte Uint8Array

const authToken = await sign({
  signer: wallet, // or keyPair.toString()
  accountId: "test.near", // if using keypair
  recipient: "your-service.near",
  nonce: customNonce, // Provide your 32-byte Uint8Array
  message: "do something with custom nonce"
});

try {
  const result = await verify(authToken, {
    expectedRecipient: "your-service.near",
    validateNonce: (nonceFromToken: Uint8Array): boolean => {
      // Your custom validation logic, e.g., check against a list of used nonces
      console.log("Validating nonce:", nonceFromToken);
      // For this example, just ensure it matches the one we sent (not a real validation)
      return nonceFromToken.every((val, idx) => val === customNonce[idx]);
    }
  });
  console.log('Message with custom nonce:', result.message);
} catch (error: any) {
  console.error('Verification with custom nonce failed:', error.message);
}
```

## Debugging

You can use the `parseAuthToken` helper method to inspect the content of the generated token.

```typescript
import { parseAuthToken, type NearAuthTokenPayload } from "near-sign-verify";

// Assuming authToken is a string from sign()
const tokenData: NearAuthTokenPayload = parseAuthToken(authToken);
console.log("Decoded token data:", tokenData);
// Access fields like tokenData.signed_message_content, tokenData.state, etc.
```

## NEP-413 Alignment

This library aims to be compatible with the signing and verification logic outlined in [NEP-413](https://github.com/near/NEPs/blob/master/neps/nep-0413.md).
It exports core NEP-413 types like `SignMessageParams`, `SignedMessage`, and `SignedPayload` for developers who might need them for deeper integration or wallet development. The `WalletInterface` is designed around these NEP-413 types.
