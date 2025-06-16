<!-- markdownlint-disable MD014 -->
<!-- markdownlint-disable MD033 -->
<!-- markdownlint-disable MD041 -->
<!-- markdownlint-disable MD029 -->

<div align="center">

<h1 style="font-size: 2.5rem; font-weight: bold;">near-sign-verify</h1>

  <p>
    <strong>Create and validate <a href="https://github.com/near/NEPs/blob/master/neps/nep-0413.md" target="_blank">NEP-413</a> signed messages for API authentication</strong>
  </p>

</div>

```bash
npm install near-sign-verify
```

> [!IMPORTANT]
>
> It is **highly recommended** that you implement state and nonce validation, initiated by a handshake with your backend. This crucial step helps mitigate [CSRF attacks](https://auth0.com/docs/secure/attack-protection/state-parameters) and [replay attacks](https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post/mitigate-replay-attacks-when-using-the-implicit-flow). The [Full Backend Integration](#3-full-backend-integration-recommended-for-production) example below demonstrates this secure flow.
>

## Cookbook

### 1. Simple Client-Side Signing with a Wallet

This example shows how to use `fastintear` (or any wallet object that implements `signMessage` as per [NEP-413](https://github.com/near/NEPs/blob/master/neps/nep-0413.md)) to sign a message client-side, attach the token to an Authorization header, and verify it with default settings.

This simple strategy is fine for a non-production application and provides a basic timestamp-based nonce validation.

```typescript
import * as near from "fastintear"; // or any wallet object that implements signMessage
import { sign, verify } from 'near-sign-verify';

// --- Client-side: Create signed token from wallet ---

const authToken = await sign("login attempt", {
  signer: near, // has signMessage method
  recipient: 'your-service.near', // can be a NEAR account ID or a URL/domain
});

// --- Client-side: Send request with the token ---

fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});

// --- Server-side: Verify the token ---

try {
  const result = await verify(authToken, {
    expectedRecipient: "your-service.near", // Ensure token is for your service
    nonceMaxAge: 300000,                    // Nonce valid for 5 minutes since message signed
    // expectedMessage: "login attempt",    // Optional: Validate the message content
  });

  // If verification is successful, you get a VerificationResult
  console.log('Successfully verified for account:', result.accountId);
  // Example: you.near
  console.log('Message from token:', result.message);
  // Example: 'login attempt' (or whatever message was originally signed)

} catch (error: any) {
  // If verification fails, an error is thrown
  console.error('Token verification failed:', error.message);
}
```

### 2. Signing with a KeyPair

This flow demonstrates signing a message using a `KeyPair` directly. This is useful for testing, backend-initiated signing (if you manage keys securely, such as when building a wallet), or simulated environments.

**Important:** [NEP-413](https://github.com/near/NEPs/blob/master/neps/nep-0413.md#why-using-a-fullaccess-key-why-not-simply-creating-an-functioncall-key-for-signing) standard explicitly states that messages **MUST be signed using a Full Access Key** for security. While `near-sign-verify` can verify signatures from Function Call Access Keys by setting `requireFullAccessKey: false`, this is **NOT recommended for production authentication flows** without significant additional validation on your end.

```typescript
// --- Create signed token from KeyPair ---
import { sign } from "near-sign-verify";
import { KeyPair } from '@near-js/crypto';

const fullAccessKeyPair = KeyPair.fromRandom('ed25519'); // example
const accountId = "you.near"; // account associated with key pair

const authToken = await sign("login attempt", {
  signer: fullAccessKeyPair.toString(),
  accountId: accountId, // Public key owner
  recipient: "your-service.near", // Can be a NEAR account ID or a URL/domain
});

// --- Send request with the token ---

fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});

// --- Verify the token ---

try {
  const result = await verify(authToken, {
    expectedRecipient: "your-service.near",
    // requireFullAccessKey: true, // Default, but able to override at your own risk
    nonceMaxAge: 300000,
  });

  console.log('Successfully verified for account:', result.accountId);
  console.log('Message from token:', result.message);

} catch (error: any) {
  console.error('Token verification failed:', error.message);
}
```

### 3. Full Backend Integration (Recommended for Production)

This strategy leverages your backend to manage nonces and states, providing the highest level of security against replay and CSRF attacks.

**Flow:**

1. **Client Request:** Frontend requests authentication parameters (message, nonce, state) from the backend.
2. **Backend Generates:** Backend generates a unique nonce and state, stores them, and sends them to the frontend.
3. **Client Signs:** Frontend uses these parameters to sign the message with the NEAR wallet.
4. **Client Sends Signed Token:** Frontend sends the `authToken` back to the backend.
5. **Backend Verifies:** Backend verifies the `authToken`, strictly validating the nonce and state against its stored values.

```typescript
// --- Client-side ---
import { sign } from "near-sign-verify";

onClick("Login with NEAR Button", async () => {
  // Step 1 & 2: Client requests auth parameters from Backend
  // Backend generates and stores state/nonce, then returns them.
  const response = await fetch("https://your-service.com/api/auth/initiate-login");
  const { state, message, nonce, recipient } = await response.json();

  // Step 3: Client signs the message using the wallet (e.g., fastintear or similar)
  const authToken = await sign(message, {
    signer: wallet, // Your wallet object (e.g., from fastintear)
    recipient: recipient, // From backend
    nonce: new Uint8Array(nonce), // Nonce from backend (ensure it's Uint8Array)
    state: state, // State from backend
    // callbackUrl: callbackUrl, // Optional, if flow requires a backend redirect
  });

  // Step 4: Client sends the signed token to backend for verification
  const verifyResponse = await fetch("https://your-service.com/api/auth/verify-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ authToken }),
  });

  if (verifyResponse.ok) {
    console.log("Authentication successful!");
    // Redirect user or update UI
  } else {
    console.error("Authentication failed:", await verifyResponse.json());
  }
});

// --- Server-side ---

// Your database/store for temporary auth requests
const authRequests = new Map(); // Use a real persistent store like Redis/DB in production
const usedNonces = new Set<string>(); // example

// Endpoint to initiate login flow
POST("https://your-service.com/api/auth/initiate-login", (req, res) => {
  const state = crypto.randomBytes(16).toString('hex'); // Generate secure random state
  const nonce = crypto.randomBytes(32); // Generate secure random 32-byte nonce
  const message = "Authorize my app";
  const recipient = "your-service.com";

  // Store the request details for later verification
  authRequests.set(state, {
    nonce: Array.from(nonce),
    message: message,
    recipient: recipient,
    timestamp: Date.now() 
  });

  res.json({
    state: state,
    message: message, // The message the user will see and sign
    nonce: Array.from(nonce), // Send as array for JSON
    recipient: recipient
  });
});

// Endpoint to verify signed token
POST("https://your-service.com/api/auth/verify-request", async (req, res) => {
  const { authToken } = req.body;

  try {
    const parsedData = parseAuthToken(authToken); // Helper to get nonce/state from token
    const {
      nonce: receivedNonce,
      state: receivedState,
      message: receivedMessage,
      recipient: receivedRecipient
    } = parsedData;

    // Retrieve stored data using the received state as key
    const storedAuthRequest = authRequests.get(receivedState);

    // Step 3: Verify the token using custom validation functions
    const result = await verify(authToken, {
      expectedState: storedAuthRequest.state // Ensure state from token matches the one used to retrieve storedAuthRequest
      validateNonce: (nonceFromToken: Uint8Array): boolean => {
        const expectedNonceForState = new Uint8Array(storedAuthRequest.nonce);
        
        // Convert nonces to comparable strings (e.g., hex)
        const receivedNonceHex = toHex(nonceFromToken);
        const expectedNonceHex = toHex(expectedNonceForState);

        // Does this nonce match the one we have stored for this state?
        if (receivedNonceHex !== expectedNonceHex) {
          console.error("Nonce mismatch: Received nonce does not match expected nonce for the state.");
          return false;
        }

        // Has this nonce already been used?
        if (usedNonces.has(receivedNonceHex)) {
          console.error("Nonce already used (replay attack detected).");
          return false;
        }
        
        // If all checks pass for this nonce, mark as used
        usedNonces.add(receivedNonceHex);
        return true;
      },
      expectedMessage: storedAuthRequest.message, // Ensure message matches what was sent to client
      // validateMessage: (message:string) => boolean // optionally, more complex message validation
      validateRecipient: (recipientFromToken: string): boolean => {
        // Example, recipient belongs to a list
        const ALLOWED_LIST = ["your-service.com", "app.your-service.com", "your-service.near"];
        return ALLOWED_LIST.includes(recipientFromToken);
      }
    });

    // If verify is successful (all validations returned true and crypto verification passed):
    // Clean up the used auth request to prevent reuse of the state/nonce
    authRequests.delete(receivedState); 
    res.json({ success: true, accountId: result.accountId, message: result.message });

  } catch (e: any) {
    // This catch block handles errors from `verify` itself (e.g., signature mismatch,
    // or if a custom validator throws an error or returns false).
    console.error("Token verification failed:", e.message);
    // If state was involved, consider cleaning up authRequests entry if error is specific to it
    if (receivedState && authRequests.has(receivedState)) {
      authRequests.delete(receivedState);
    }
    res.status(400).json({ success: false, error: e.message });
  }
```

## Debugging

You can use the `parseAuthToken` helper method to inspect the outcome of `sign`.

```typescript

import { parseAuthToken, type NearAuthData } from "near-sign-verify";

const authHeader = c.req.header('Authorization');

const authToken = authHeader.substring(7);

const authData: NearAuthData = parseAuthToken(authToken);

console.log("authData", authData);
```
