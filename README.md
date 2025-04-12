# near-sign-verify

Creates and validates NEAR signatures for API authentication.

```bash
npm install near-sign-verify
```

```typescript
import { generateNonce, createAuthToken, validateSignature } from 'near-sign-verify';

// Generate nonce & sign
const nonce = generateNonce();
const message = JSON.stringify({
  nonce,
  recipient: 'them.near',
  timestamp: Date.now(),
});

const signed = await nearWallet.signMessage(message);

// Create token
const authToken = createAuthToken({
  account_id: 'you.near',
  public_key: signed.publicKey,
  signature: signed.signature,
  message,
  nonce,
  recipient: signed.recipient,
});

// Send request
fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});

// Parse token
const authData = parseAuthToken(authToken);

// Validate
const isValid = await validateSignature(authData);
```
