# near-sign-verify

Creates and validates NEAR wallet signatures for API authentication.

```bash
npm install near-sign-verify
```

## Usage

### Create Auth Data

```typescript
import { createAuthToken } from 'near-sign-verify';

const authToken = createAuthToken({
  account_id: 'you.near',
  public_key: 'ed25519:pubkey',
  signature: 'sig',
  message: 'msg',
  nonce: 'nonce',
  recipient: 'recipient.near',
});

fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});
```

### Validate Signature

```typescript
import { validateSignature } from 'near-sign-verify';

const isValid = await validateSignature({
  signature: 'sig-to-validate',
  message: 'signed-message',
  publicKey: 'ed25519:pubkey',
  nonce: 'nonce',
  recipient: 'recipient.near',
});
```

### Complete Flow

```typescript
import { generateNonce, createAuthToken, validateSignature } from 'near-sign-verify';

// Client: Generate nonce & sign
const nonce = generateNonce();
const message = JSON.stringify({
  nonce,
  recipient: 'recipient.near',
  timestamp: Date.now(),
});

const signed = await nearWallet.signMessage(message);

// Create token & send request
const authToken = createAuthToken({
  account_id: 'you.near',
  public_key: signed.publicKey,
  signature: signed.signature,
  message,
  nonce,
  recipient: 'recipient.near',
});

fetch('https://api.example.com/endpoint', {
  headers: { 'Authorization': `Bearer ${authToken}` },
});

// Server: Validate
const isValid = await validateSignature({
  signature: signed.signature,
  message,
  publicKey: signed.publicKey,
  nonce,
  recipient: 'recipient.near',
});
```

### Utils

```typescript
import {
  generateNonce,
  validateNonce,
  stringToUint8Array,
  uint8ArrayToString,
  base64ToUint8Array,
  uint8ArrayToBase64,
} from 'near-sign-verify';
```

## License

MIT