// generate-keys.js
import { generateKeyPairSync } from 'crypto';
import { writeFileSync } from 'fs';

// Generate an RSA key pair
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Export the private key as JWK (includes all necessary parameters)
const privateJwk = privateKey.export({ format: 'jwk' });
privateJwk.use = 'sig';
privateJwk.kid = 'oidc-provider-key-1';
privateJwk.alg = 'RS256';

// Create the JWKS with the private key
const jwks = {
  keys: [privateJwk],
};

// Write the JWKS to jwks.json
writeFileSync('jwks.json', JSON.stringify(jwks, null, 2));

console.log('JWKS generated and saved to jwks.json');
