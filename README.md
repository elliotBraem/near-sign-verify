# near-sign-verify

Creates and validates NEAR signatures for API authentication.

```bash
npm install near-sign-verify
```

```typescript
import { sign, verify } from 'near-sign-verify';
import { KeyPair } from '@near-js/crypto'; // For KeyPair example

  // --- Signer Setup (using KeyPair for this example) ---
const keyPair = KeyPair.fromRandom('ed25519');
const accountId = 'you.near'; // Your account ID
const recipient = 'your-service.near'; // The intended recipient of the auth token

// --- Sign to create an Auth Token ---
// The 'sign' function now handles message structuring internally.
// It includes a nonce, timestamp, recipient, and your optional data.
const authToken = await sign({
  signer: keyPair,
  accountId: accountId,
  recipient: recipient,
  data: { customInfo: 'login attempt' }, // Optional: any app-specific data
});

console.log('Generated Auth Token:', authToken);

// --- Send request with the token ---
// fetch('https://api.example.com/endpoint', {
//   headers: { 'Authorization': `Bearer ${authToken}` },
// });

// --- Verify the Auth Token (typically on a backend) ---
try {
  const verificationResult = await verify(authToken, {
    expectedRecipient: recipient, // Ensure token is for your service
    requireFullAccessKey: false,  // Allow Function Call Access Keys
    nonceMaxAge: 300000,          // 5 minutes
  });

  // If verification is successful, you get a VerificationResult
  console.log('Successfully verified for account:', verificationResult.accountId);
  console.log('Message data from token:', verificationResult.messageData);
  // verificationResult.messageData.data will contain { customInfo: 'login attempt' }

} catch (error: any) {
  // If verification fails, an error is thrown
  console.error('Token verification failed:', error.message);
}

// --- Optional: Parse token without full verification (for debugging) ---
// try {
//   const parsedData = parseAuthToken(authToken);
//   console.log('Parsed token (no signature check):', parsedData.accountId, parsedData.message);
// } catch (e: any) {
//   console.error('Failed to parse token:', e.message);
// }

const walletToken = await sign({ signer: myWallet, recipient: 'app.near', data: { ... } });
```

## TODO

- [ ] signverify.near.page - easy to use methods; sample of adding key to a server?
