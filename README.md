# near-simple-signing

NEAR wallet signature generation and validation utility for API authentication.

## Overview

This package provides a simple way to create and validate NEAR wallet signatures for authentication with APIs. It works in both browser and server environments, and is compatible with Node.js, browsers, and Deno.

## Features

- Create properly formatted authentication headers
- Validate signatures
- Generate and validate nonces
- Environment-agnostic implementation (works in browsers, Node.js, and Deno)
- No dependencies on near-api-js

## Installation

```bash
# Using npm
npm install near-simple-signing

# Using yarn
yarn add near-simple-signing

# Using pnpm
pnpm add near-simple-signing

# Using bun
bun add near-simple-signing
```

## Usage

### Creating an Authentication Header

```typescript
import { createAuthHeader } from 'near-simple-signing';

// Create an auth header from signature data
const authHeader = createAuthHeader({
  account_id: 'your-account.near',
  public_key: 'ed25519:your-public-key',
  signature: 'your-signature',
  message: 'message-that-was-signed',
  nonce: 'your-nonce',
  recipient: 'api.example.com',
});

// Use the auth header in your API requests
fetch('https://api.example.com/endpoint', {
  headers: {
    'Authorization': `NEAR ${authHeader}`,
  },
});
```

### Validating a Signature

```typescript
import { validateSignature } from 'near-simple-signing';

// Validate a signature
const result = await validateSignature({
  signature: 'signature-to-validate',
  message: 'message-that-was-signed',
  publicKey: 'ed25519:public-key',
  nonce: 'nonce-used-for-signing',
  recipient: 'api.example.com',
});

if (result.valid) {
  console.log('Signature is valid');
} else {
  console.error('Signature is invalid:', result.error);
}
```

### Utility Functions

```typescript
import {
  generateNonce,
  validateNonce,
  stringToUint8Array,
  uint8ArrayToString,
  base64ToUint8Array,
  uint8ArrayToBase64,
} from 'near-simple-signing';

// Generate a nonce
const nonce = generateNonce();

// Validate a nonce
const nonceValidation = validateNonce(nonce);

// Convert between different formats
const uint8Array = stringToUint8Array('Hello, world!');
const string = uint8ArrayToString(uint8Array);
const base64 = uint8ArrayToBase64(uint8Array);
const backToUint8Array = base64ToUint8Array(base64);
```

## API Reference

### `createAuthHeader(authData)`

Creates an authentication header for API requests.

**Parameters:**
- `authData`: An object containing:
  - `account_id`: NEAR account ID
  - `public_key`: Public key used for signing
  - `signature`: Signature of the message
  - `message`: Message that was signed
  - `nonce`: Nonce used for signing
  - `recipient` (optional): Recipient of the message
  - `callback_url` (optional): Callback URL

**Returns:** A string containing the authentication header.

### `validateSignature(params)`

Validates a signature.

**Parameters:**
- `params`: An object containing:
  - `signature`: Signature to validate
  - `message`: Message that was signed
  - `publicKey`: Public key to validate against
  - `nonce`: Nonce used for signing
  - `recipient` (optional): Recipient of the message

**Returns:** A promise that resolves to a validation result object with:
- `valid`: Whether the signature is valid
- `error` (optional): Error message if invalid

### Utility Functions

- `generateNonce()`: Generates a nonce for signing
- `validateNonce(nonce)`: Validates a nonce
- `stringToUint8Array(str)`: Converts a string to Uint8Array
- `uint8ArrayToString(arr)`: Converts a Uint8Array to string
- `base64ToUint8Array(base64)`: Converts a base64 string to Uint8Array
- `uint8ArrayToBase64(arr)`: Converts a Uint8Array to base64 string

## License

MIT
