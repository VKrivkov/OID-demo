// oidc-demo/idp.js
import Provider from 'oidc-provider';
import express from 'express';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import https from 'https';
import MemoryAdapter from './adapter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'form-action': ["'self'", 'https://localhost:3000'],
        'connect-src': ["'self'", 'https://localhost:3000'],
      },
    },
  })
);// Load JWKS
const jwks = JSON.parse(fs.readFileSync(path.join(__dirname, 'jwks.json'), 'utf-8'));

// Simulated user database
const users = [
  {
    id: 'user1',
    username: 'alice',
    password: '123',
    name: 'Alice',
    email: 'alice@example.com',
  },
  {
    id: 'user2',
    username: 'bob',
    password: 'password456',
    name: 'Bob',
    email: 'bob@example.com',
  },
  // Add more users as needed
];

// OIDC Provider configuration
const configuration = {
  clients: [
    {
      client_id: 'client_app',
      client_secret: 'client_secret',
      redirect_uris: ['https://localhost:3000/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      require_pkce: true,
    }
  ],

  adapter: MemoryAdapter,

  cookies: {
    keys: ['some secret key', 'and also the old rotated away some time ago', 'and one more'],
    long: { signed: true, secure: false },
    short: { signed: true, secure: false }
    },

  jwks,

  claims: {
    openid: ['sub'],
    profile: ['name', 'email'],
    email: ['email', 'email_verified'],
  },

  scopes: ['openid', 'profile', 'email'],

  findAccount: async (ctx, id) => {
    const user = users.find((u) => u.id === id);
    if (!user) return undefined;
    return {
      accountId: id,
      async claims(use, scope) {
        const claims = { sub: id };
        if (scope.includes('profile')) {
          claims.name = user.name;
        }
        if (scope.includes('email')) {
          claims.email = user.email;
          claims.email_verified = true;
        }
        return claims;
      },
    };
  },

  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
    ttl: {
      AccessToken: 3600, // 1 hour
    AuthorizationCode: 600, // 10 minutes
    IdToken: 3600, // 1 hour
    RefreshToken: 86400, // 1 day
    Grant: 1209600, // 14 days
    Interaction: 3600, // 1 hour
    Session: 604800, // 7 days
    DeviceCode: 600, // 10 minutes
    },
  },

  features: {
    devInteractions: { enabled: false }, // Disable default interactions
  },
};

const oidc = new Provider('https://localhost:4000', configuration);

// View engine setup (EJS)
app.set('views', path.join(__dirname, '../views')); // Adjust the path to '../views'
app.set('view engine', 'ejs');

// Interaction routes
app.get('/interaction/:uid', async (req, res, next) => {
  try {
    const details = await oidc.interactionDetails(req, res);
    const { uid, prompt, params } = details;
    const client = await oidc.Client.find(params.client_id);

    if (prompt.name === 'login') {
      // Render the login form
      res.render('login', {
        client,
        uid,
        details: prompt.details,
        params,
        title: 'Sign-in',
      });
    } else if (prompt.name === 'consent') {
      // Render the consent form
      res.render('consent', {
        client,
        uid,
        details: prompt.details,
        params,
        title: 'Authorize',
      });
    } else {
      // Handle other prompts if necessary
      res.status(501).send('Interaction not supported');
    }
  } catch (err) {
    next(err);
  }
});


app.post('/interaction/:uid/login', async (req, res, next) => {
  try {
    console.log('POST /interaction/:uid/login called with UID:', req.params.uid);

    console.log('Received POST data:', req.body); 

    const details = await oidc.interactionDetails(req, res);
    const { uid, prompt, params } = details;
    const client = await oidc.Client.find(params.client_id);

    const { username, password } = req.body;

    // Implement user authentication logic
    const user = users.find((u) => u.username === username && u.password === password);

    if (!user) {
      // Authentication failed
      res.status(401).send('Invalid username or password');
      return;
    }

    const result = {
      login: {
        accountId: user.id,
      },
    };
    console.log('Result data:', result); 

    await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    next(err);
  }
});

app.post('/interaction/:uid/confirm', async (req, res, next) => {
  try {
    const details = await oidc.interactionDetails(req, res);
    const { uid, prompt, params, session } = details;

    const grant = new oidc.Grant({
      accountId: session.accountId,
      clientId: params.client_id,
    });

    if (params.scope) {
      grant.addOIDCScope(params.scope);
    }

    const grantId = await grant.save();

    const result = { consent: { grantId } };

    await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
  } catch (err) {
    next(err);
  }
});


app.post('/interaction/:uid/abort', async (req, res, next) => {
  try {
    const result = {
      error: 'access_denied',
      error_description: 'End-User aborted interaction',
    };
    await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    next(err);
  }
});


// Mount the OIDC provider
app.use(oidc.callback());

// Load SSL/TLS certificates
const options = {
  key: fs.readFileSync(path.join(__dirname, 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
};

oidc.on('token.issued', (token) => {
  if (token.kind === 'AccessToken' || token.kind === 'RefreshToken' || token.kind === 'IdToken') {
    console.log(`JWT issued (${token.kind}): ${token}`);
  }
});


// Start the HTTPS server
https.createServer(options, app).listen(4000, () => {
  console.log('OIDC Provider listening on port 4000');
});
