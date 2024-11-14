// idp.js
import Provider from 'oidc-provider';
import express from 'express';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { typeormAdapter, initializeAdapter } from './adapter.js'; // Ensure your adapter is correctly set up
import fs from 'fs';
import path from 'path';
import https from 'https'; // Import the https module


// Paths to JWKS
const jwksPath = path.join(process.cwd(), 'jwks.json');

// Function to ensure key files exist
const ensureKeyFilesExist = () => {
  if (!fs.existsSync(jwksPath)) {
    console.error(
      'JWKS file not found. Please run "node generate-keys.js" first.'
    );
    process.exit(1);
  }
};

// Load JWKS (Private Keys)
const loadJwks = () => {
  try {
    const jwksData = fs.readFileSync(jwksPath, 'utf-8');
    const jwks = JSON.parse(jwksData);

    // Validate JWKS structure
    if (!jwks.keys || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
      throw new Error('JWKS must contain at least one key in the "keys" array.');
    }

    // Validate each key has required properties for private keys
    jwks.keys.forEach((key, index) => {
      const requiredProps = [
        'kty', 'kid', 'use', 'alg', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi',
      ];
      requiredProps.forEach((prop) => {
        if (!key[prop]) {
          throw new Error(
            `Private key at index ${index} is missing required property: ${prop}`
          );
        }
      });
    });

    return jwks;
  } catch (err) {
    console.error('Error loading JWKS:', err.message);
    process.exit(1);
  }
};

// Ensure key files exist before proceeding
ensureKeyFilesExist();

// Load keys
const jwks = loadJwks();

// Generate or load cookies keys
const generateSecureKeys = () => {
  const key1 = crypto.randomBytes(32).toString('hex');
  const key2 = crypto.randomBytes(32).toString('hex');
  return [key1, key2];
};
const cookiesKeys = generateSecureKeys();

// Define OIDC Provider configuration
const configuration = {
  // **1. Clients Configuration**
  clients: [
    {
      client_id: 'client_app',
      client_secret: 'client_secret',
      redirect_uris: ['https://localhost:3000/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      // Enforce PKCE
      require_pkce: true,
    },
    // Add more clients (RPs) here
  ],

  // **2. Cookies Configuration**
  cookies: {
    keys: cookiesKeys, // Array of keys for signing cookies
    long: {
      signed: true,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
      sameSite: 'lax',
    },
    short: {
      signed: true,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
      sameSite: 'lax',
    },
  },

  // **3. JWKS Configuration (Private Keys)**
  jwks, // Use the custom JWKS with private keys

  // **4. Interaction Configuration**
  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
    ttl: {
      Login: 3600, // 1 hour in seconds
      Consent: 3600,
    },
  },

  // **5. Features Configuration**
  features: {
    // Disable devInteractions since we're implementing custom interactions
    devInteractions: { enabled: false },
    // Enable other features as needed
    // Example:
    // registration: { enabled: true },
    // introspection: { enabled: true },
    // revocation: { enabled: true },
  },

  // **6. Claims Configuration**
  claims: {
    openid: ['sub'],
    profile: [
      'name',
      'family_name',
      'given_name',
      'middle_name',
      'nickname',
      'preferred_username',
      'profile',
      'picture',
      'website',
      'gender',
      'birthdate',
      'zoneinfo',
      'locale',
      'updated_at',
    ],
    email: ['email', 'email_verified'],
    // Add custom claims as needed
  },

  // **7. Scope Configuration**
  scopes: ['openid', 'profile', 'email'],

  renderError(ctx, out, error) {
    console.error('OIDC Provider Error:', error);
    ctx.type = 'html';
    ctx.body = `<h1>Server Error</h1><p>${error.message}</p>`;
  },
};

// Initialize Express App
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json()); // To parse JSON bodies
app.use(helmet());

// **Rate Limiting Middleware**
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// **Helper Functions for Advanced Features**
// Placeholder implementations; replace with actual logic as needed
const generateVerifiableCredential = (credentialRequest) => {
  // TODO: Implement VC generation logic
  return { /* Verifiable Credential Object */ };
};

const verifyVerifiablePresentation = (credentialPresentation) => {
  // TODO: Implement VP verification logic
  return true; // or false based on verification
};

const generateZKP = async (data) => {
  // TODO: Implement Zero-Knowledge Proof generation logic
  return { /* Proof Object */ };
};

const verifyZKP = async (proof) => {
  // TODO: Implement Zero-Knowledge Proof verification logic
  return true; // or false based on verification
};

const verifyWalletAttestation = async (walletData) => {
  // TODO: Implement Wallet Attestation verification logic
  return true; // or false based on verification
};

// **Initialize Adapter and OIDC Provider**
const startServer = async () => {
  try {
    // Initialize the TypeORM adapter (database connection)
    await initializeAdapter();

    // Create the OIDC Provider with the TypeORM adapter
    const oidc = new Provider('https://localhost:4000', {
      ...configuration,
      adapter: typeormAdapter, // Pass the factory function
    });

    // **Custom Interaction Routes**
    // Handle interaction display (login form)
    app.get('/interaction/:uid', async (req, res, next) => {
      try {
        const { uid, prompt, params } = await oidc.interactionDetails(req, res);
        const client = await oidc.Client.find(params.client_id);

        console.log(`Starting interaction for UID: ${uid}, prompt: ${prompt.name}`);

        // Render a simple login form
        res.send(`
          <html>
            <body>
              <h1>Login</h1>
              <form method="post" action="/interaction/${uid}/login">
                <label>Username:</label>
                <input name="username" type="text" required/><br/>
                <label>Password:</label>
                <input name="password" type="password" required/><br/>
                <button type="submit">Submit</button>
              </form>
            </body>
          </html>
        `);
      } catch (err) {
        next(err);
      }
    });

    // Handle login form submission
    app.post('/interaction/:uid/login', async (req, res, next) => {
      try {
        const { uid, prompt, params } = await oidc.interactionDetails(req, res);
        const client = await oidc.Client.find(params.client_id);

        const { username, password } = req.body;

        console.log(`Login attempt for UID: ${uid}, username: ${username}`);


        // TODO: Implement actual user authentication logic
        // For demo purposes, accept any username/password
        const accountId = username; // Replace with actual user ID after authentication

        const result = {
          login: {
            account: accountId,
          },
        };

         await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
        console.log(`Interaction ${uid} completed successfully for account: ${accountId}`);
      } catch (err) {
        console.error('Error in login interaction:', err);
        next(err);
      }
    });

    // **Advanced Features: OID4VCI and OID4VP**
    // Placeholder for implementing OID4VCI and OID4VP
    app.post('/issue-credential', async (req, res) => {
      const { credentialRequest } = req.body;

      // TODO: Validate the credential request and generate VC
      const verifiableCredential = generateVerifiableCredential(credentialRequest);

      res.json({ credential: verifiableCredential });
    });

    app.post('/present-credential', async (req, res) => {
      const { credentialPresentation } = req.body;

      // TODO: Validate the credential presentation and verify VP
      const isValid = verifyVerifiablePresentation(credentialPresentation);

      res.json({ valid: isValid });
    });

    // **Selective Disclosure and ZKP Endpoints**
    app.post('/generate-proof', async (req, res) => {
      const { data } = req.body;
      const proof = await generateZKP(data);
      res.json({ proof });
    });

    app.post('/verify-proof', async (req, res) => {
      const { proof } = req.body;
      const isValid = await verifyZKP(proof);
      res.json({ isValid });
    });

    // **Wallet Attestations**
    app.post('/register-wallet', async (req, res) => {
      const { walletData } = req.body;

      // TODO: Verify walletData using attestation services
      const isValid = await verifyWalletAttestation(walletData);

      if (isValid) {
        // Issue wallet-specific credentials or tokens
        res.json({ status: 'Wallet registered successfully' });
      } else {
        res.status(400).json({ error: 'Invalid wallet attestation' });
      }
    });

    // **Attach OIDC Provider to Express app**
    app.use(oidc.callback());

    // **Start the Express Server**
    // Load SSL/TLS certificates
    const options = {
      key: fs.readFileSync('rp-demo/key.pem'),
      cert: fs.readFileSync('rp-demo/cert.pem'),
    };

    // Start the HTTPS server
    https.createServer(options, app).listen(4000, () => {
      console.log('OIDC Provider listening on port 4000');
    });

  } catch (err) {
    console.error('Failed to initialize adapter or start server:', err);
    process.exit(1);
  }
};

// Start the server
startServer();
