/* eslint-disable no-console */
const express = require('express');
const crypto = require('crypto');
const helmet = require('helmet');
const path = require('path');
const NodeCache = require('node-cache');
const cookieParser = require('cookie-parser');
const cookieEncrypter = require('cookie-encrypter');
const mustacheExpress = require('mustache-express');
const cors = require('cors');
const { Issuer, generators } = require('openid-client');

const {
  FRONTEND_URL,
  OIDC_AUTHORITY,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
} = process.env;

let {
  PORT,
  LISTEN_ADDRESS,
  COOKIE_SECRET_KEY,
} = process.env;

PORT = PORT || 8080;
LISTEN_ADDRESS = LISTEN_ADDRESS || '0.0.0.0';

if (!COOKIE_SECRET_KEY) {
  COOKIE_SECRET_KEY = crypto.randomBytes(16).toString('hex');
}

const app = express();
app.use(express.urlencoded());
app.set('views', path.join(__dirname, 'views'));
app.engine('html', mustacheExpress());
app.set('view engine', 'html');
app.use(
  helmet({
    permittedCrossDomainPolicies: false,
    hsts: false,
    contentSecurityPolicy: false,
  }),
);
app.use(cookieParser(COOKIE_SECRET_KEY));
app.use(cookieEncrypter(COOKIE_SECRET_KEY));
app.use(cors({
  allowedHeaders: 'Authorization',
  methods: 'HEAD,GET,POST',
}));

let CLIENT;

const AUTHENTICATION_REQUEST_CACHE = new NodeCache({ stdTTL: 60 * 5 });
const AUTHENTICATED_NONCE_CACHE = new NodeCache({ stdTTL: 60 });

// will no longer be needed in Express.js 5
function runAsyncWrapper(callback) {
  return (req, res, next) => {
    callback(req, res, next)
      .catch(next);
  };
}

app.get('/.well-known/openid-configuration', (req, res) => {
  const configuration = {
    issuer: FRONTEND_URL,
    authorization_endpoint: `${FRONTEND_URL}/auth`,
    token_endpoint: `${FRONTEND_URL}/token`,
    userinfo_endpoint: `${FRONTEND_URL}/userinfo`,
    introspection_endpoint: `${FRONTEND_URL}/introspect`,
    jwks_uri: `${FRONTEND_URL}/certs`,
    check_session_iframe: `${FRONTEND_URL}/check_session_iframe.html`,
    response_types_supported: [
      'code',
    ],
    subject_types_supported: [
      'public',
    ],
    id_token_signing_alg_values_supported: [
      'RS256',
    ],
    scopes_supported: [
      'openid',
      'email',
      'profile',
      'boat_key',
    ],
    claims_supported: [
      'aud',
      'email',
      'exp',
      'iat',
      'iss',
      'name',
      'sub',
    ],
    grant_types_supported: [
      'authorization_code',
    ],
  };

  res.json(configuration);
});

app.get('/auth', runAsyncWrapper(async (req, res) => {
  const nonce = crypto.randomBytes(16).toString('hex');

  AUTHENTICATION_REQUEST_CACHE.set(nonce, {
    redirect_uri: req.query.redirect_uri,
    state: req.query.state,
    code_challenge: req.query.code_challenge,
  });

  const qrLoginUrl = `${FRONTEND_URL}/qr-auth?nonce=${nonce}`;

  res.render('auth', {
    nonce,
    qr_login_url: qrLoginUrl,
    encoded_qr_login_url: encodeURIComponent(qrLoginUrl),
    check_qr_authorization_url: `${FRONTEND_URL}/check_qr_authorization?nonce=${nonce}`,
  });
}));

app.get('/qr-auth', runAsyncWrapper(async (req, res) => {
  const { nonce } = req.query;
  if (!nonce) {
    res.status(400).send('Missing nonce');
    return;
  }

  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);

  const redirectUri = CLIENT.authorizationUrl({
    scope: 'openid email profile',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: nonce,
  });

  res.cookie('code_verifier', codeVerifier, {
    signed: true,
    maxAge: 1000 * 60 * 5,
    httpOnly: true,
  });

  res.redirect(redirectUri);
}));

app.get('/qr-cb', runAsyncWrapper(async (req, res) => {
  const params = CLIENT.callbackParams(req);
  const nonce = params.state;
  const codeVerifier = req.signedCookies.code_verifier;

  const tokenSet = await CLIENT.callback(`${FRONTEND_URL}/qr-cb`, params, {
    code_verifier: codeVerifier,
    state: nonce,
    response_type: 'code',
  });
  console.log('received and validated tokens %j', tokenSet);
  console.log('validated ID Token claims %j', tokenSet.claims());

  const userinfo = await CLIENT.userinfo(tokenSet.access_token);

  AUTHENTICATED_NONCE_CACHE.set(nonce, tokenSet.refresh_token);

  res.send(`User: ${userinfo.name}`);
}));

// const hmac = crypto.createHmac('SHA2', COOKIE_SECRET_KEY);
// hmac.update(NONCE_CACHE.take(nonce));
// const session = hmac.digest('base64');

app.get('/check_qr_authorization', runAsyncWrapper(async (req, res) => {
  const { nonce } = req.query;

  if (AUTHENTICATED_NONCE_CACHE.has(nonce)) {
    res.send({
      authenticated: true,
      callback_url: `${FRONTEND_URL}/check_qr_callback?nonce=${nonce}`,
    });
  } else {
    res.send({ authenticated: false });
  }
}));

app.get('/check_qr_callback', runAsyncWrapper(async (req, res) => {
  const { nonce } = req.query;

  const requestInfo = AUTHENTICATION_REQUEST_CACHE.get(nonce);
  const redirectUri = `${requestInfo.redirect_uri}?state=${requestInfo.state}&code=${nonce}`;

  res.cookie('session', `qr_${nonce}`, {
    signed: true,
    maxAge: 1000 * 60 * 5,
  });
  res.redirect(redirectUri);
}));

(async function configureOIDC() {
  const authority = await Issuer.discover(OIDC_AUTHORITY);
  console.log('Discovered authority %s %O', authority.issuer, authority.metadata);

  CLIENT = new authority.Client({
    client_id: OIDC_CLIENT_ID,
    client_secret: OIDC_CLIENT_SECRET,
    redirect_uris: [`${FRONTEND_URL}/qr-cb`],
    response_types: ['code'],
  });

  const server = app.listen(PORT, LISTEN_ADDRESS, () => {
    console.log(`Server started at ${server.address().address}:${server.address().port}`);
  });
}());
