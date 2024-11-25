// app.js
import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';
import { URL } from 'url'; // Import URL class explicitly
import https from 'https';
import fs from 'fs';

const app = express();

// Trust the self-signed certificate
const caCert = fs.readFileSync('cert.pem');
const httpsAgent = new https.Agent({ ca: caCert, rejectUnauthorized: false });

const redirect_uri = 'https://localhost:3000/callback';
const clientId = 'client_app';
const clientSecret = 'client_secret';

// Configure session middleware
app.use(
  session({
    secret: 'some-super-secret-key', // Replace with a secure secret in production
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize OIDC client configuration
let config;

(async () => {
  try {
    const server = new URL('https://localhost:4000'); // OIDC provider URL
    const clientAuthentication = client.ClientSecretBasic(clientSecret);

    
    // Discover the issuer configuration using client.discovery
    config = await client.discovery(server, clientId, undefined, clientAuthentication, httpsAgent );

    app.locals.oidcClient = config;
    console.log('OIDC configuration discovered successfully.');
  } catch (err) {
    console.error('Failed to discover issuer:', err);
  }
})();

// Home route
app.get('/', (req, res) => {
  if (req.session.tokenSet) {
    res.send(`
      <h1>Welcome back</h1>
      <p>You are logged in.</p>
      <a href="/profile">View Profile</a><br>
      <a href="/logout">Logout</a>
    `);
  } else {
    res.send(`
      <h1>Welcome</h1>
      <p>You are not logged in.</p>
      <a href="/login">Login</a>
    `);
  }
});

// Login route
app.get('/login', async (req, res) => {
  const oidcClient = req.app.locals.oidcClient;
  if (!oidcClient) {
    return res.send('OIDC client not initialized');
  }

  // Generate code_verifier and code_challenge for PKCE
  const code_verifier = client.randomPKCECodeVerifier();
  const code_challenge = await client.calculatePKCECodeChallenge(code_verifier);
  const state = client.randomState();

  // Store code_verifier and state in session
  req.session.code_verifier = code_verifier;
  req.session.state = state;

  // Create the authorization URL
  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri,
    scope: 'openid profile email',
    code_challenge,
    code_challenge_method: 'S256',
    state,
  });

  console.log('Redirecting to authorization URL:', authorizationUrl.href);

  // Redirect the user to the OIDC provider's authorization endpoint
  res.redirect(authorizationUrl.href);
});

// Callback route
app.get('/callback', async (req, res) => {
  try {
    if (!config) {
      return res.send('OIDC configuration not yet loaded.');
    }


    // Construct the full callback URL
    const currentUrl = new URL(req.protocol + '://' + req.get('host') + req.originalUrl);

    // Exchange the authorization code for tokens
    const tokens = await client.authorizationCodeGrant(
      config,
      currentUrl,
      {
        pkceCodeVerifier: req.session.code_verifier,
        expectedState: req.session.state,
      },
      undefined, // tokenEndpointParameters
      {
        clientAuthentication: client.ClientSecretBasic(clientSecret, clientId),
        agent: httpsAgent, // Include the httpsAgent to handle self-signed certificates
      }
    );
    


    // Store tokens in session
    req.session.tokenSet = tokens;

    const idTokenClaims = tokens.claims();
    req.session.expectedSubject = idTokenClaims.sub;

    console.log('Token Endpoint Response:', tokens);
    console.log('Access Token:', tokens.access_token);
    console.log('ID Token Claims:', tokens.claims());

    // Redirect to home page after successful authentication
    res.redirect('/');
  } catch (err) {
    console.error('Error in callback:', err);
    res.status(500).send('Callback error');
  }
});



// Profile route
app.get('/profile', async (req, res) => {
  const oidcClient = req.app.locals.oidcClient;
  if (!oidcClient) {
    return res.send('OIDC client not initialized');
  }

  if (!req.session.tokenSet) {
    return res.redirect('/login');
  }

  try {
    const idTokenClaims = req.session.tokenSet;
    const expectedSubject = req.session.expectedSubject;
1
    // Use the access token to request user info from the UserInfo endpoint
    const userinfo = await client.fetchUserInfo(
      config,
      req.session.tokenSet.access_token,
      expectedSubject,
      { agent: httpsAgent }
    );


    res.send(`
      <h1>Profile</h1>
      <h2>ID Token Claims</h2>
      <pre>${JSON.stringify(idTokenClaims, null, 2)}</pre>
      <h2>UserInfo</h2>
      <pre>${JSON.stringify(userinfo, null, 2)}</pre>
      <a href="/">Home</a>
    `);
  } catch (err) {
    console.error('Error retrieving profile:', err);
    res.send('Profile error');
  }
});


// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Load SSL/TLS certificates
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
};

// Start the HTTPS server
https.createServer(options, app).listen(3000, () => {
  console.log('Client app listening on port 3000');
});
