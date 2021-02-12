/* eslint-disable no-console */
const express = require('express');
const crypto = require('crypto');
const helmet = require('helmet');
const path = require('path');
const jwt = require('jsonwebtoken');
const bearerToken = require('express-bearer-token');
const NodeCache = require('node-cache');
const cookieParser = require('cookie-parser');
const mustacheExpress = require('mustache-express');
const cors = require('cors');
const NodeRSA = require('node-rsa');
const { pem2jwk } = require('pem-jwk');
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
  // COOKIE_SECRET_KEY,
  SERVER_PRIVATE_KEY,
} = process.env;

PORT = PORT || 8080;
LISTEN_ADDRESS = LISTEN_ADDRESS || '0.0.0.0';

// if (!COOKIE_SECRET_KEY) {
//   COOKIE_SECRET_KEY = crypto.randomBytes(16).toString('hex');
// }

if (!SERVER_PRIVATE_KEY) {
  SERVER_PRIVATE_KEY = new NodeRSA().generateKeyPair().exportKey('pkcs1-private-pem');
}
const SERVER_JWK = pem2jwk(SERVER_PRIVATE_KEY);
const SERVER_JWK_KEY_ID = crypto.randomBytes(16).toString('hex');

const app = express();
app.use(express.urlencoded());
app.use(bearerToken());
app.set('views', path.join(__dirname, 'views'));
app.engine('html', mustacheExpress());
app.set('view engine', 'html');
app.use(
  helmet({
    permittedCrossDomainPolicies: false,
    hsts: false,
    contentSecurityPolicy: false,
    frameguard: false,
  }),
);
app.use(cookieParser());
// app.use(cookieEncrypter(COOKIE_SECRET_KEY));
app.use(cors({
  allowedHeaders: 'Authorization',
  methods: 'HEAD,GET,POST',
}));

let CLIENT;

const AUTHENTICATION_REQUEST_CACHE = new NodeCache({ stdTTL: 60 * 60 * 24 * 30 });
const AUTHENTICATED_NONCE_CACHE = new NodeCache({ stdTTL: 60 * 30 });

// will no longer be needed in Express.js 5
function runAsyncWrapper(callback) {
  return (req, res, next) => {
    callback(req, res, next)
      .catch(next);
  };
}

async function refreshTokens(nonce) {
  if (!AUTHENTICATED_NONCE_CACHE.has(nonce)) {
    throw new Error('No such session');
  }

  const authenticationRecord = AUTHENTICATED_NONCE_CACHE.get(nonce);
  const tokenSet = await CLIENT.refresh(authenticationRecord.refresh_token);

  if (tokenSet.refresh_token) {
    authenticationRecord.refresh_token = tokenSet.refresh_token;
    AUTHENTICATED_NONCE_CACHE.set(nonce, authenticationRecord);
  } else {
    AUTHENTICATED_NONCE_CACHE.ttl(nonce);
  }

  return {
    access_token: tokenSet.access_token,
    token_type: tokenSet.token_type,
    expires_in: tokenSet.expires_in,
    nonce,
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
    end_session_endpoint: `${FRONTEND_URL}/end_session`,
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
  if (req.query.code_challenge_method !== 'S256') {
    res.redirect(`${req.query.redirect_uri}?error=invalid_request&state=${req.query.state}&error_description=code_challenge_method%20S256%20required`);
    return;
  }

  if (!req.query.code_challenge) {
    res.redirect(`${req.query.redirect_uri}?error=invalid_request&state=${req.query.state}&error_description=missing%20code_challenge`);
  }

  const { session } = req.cookies;
  let nonce;
  if (session) {
    nonce = session.substring(3);
  }
  if (AUTHENTICATED_NONCE_CACHE.has(nonce)) {
    let redirectUri;
    try {
      const code = encodeURIComponent(`${JSON.stringify(await refreshTokens(nonce))}`);
      const authenticationRecord = AUTHENTICATED_NONCE_CACHE.get(nonce);
      authenticationRecord.code_challenge = req.query.code_challenge;
      AUTHENTICATED_NONCE_CACHE.set(nonce, authenticationRecord);
      redirectUri = `${req.query.redirect_uri}?state=${req.query.state}&session_state=qr_${nonce}&code=${code}`;
    } catch (error) {
      AUTHENTICATED_NONCE_CACHE.del(nonce);
      redirectUri = `${req.query.redirect_uri}?error=invalid_request&state=${req.query.state}`;
      console.log('unable to refresh token');
    }
    res.redirect(redirectUri);
    return;
  }
  if (req.query.prompt === 'none') {
    res.redirect(`${req.query.redirect_uri}?error=login_required&state=${req.query.state}`);
    return;
  }

  nonce = crypto.randomBytes(16).toString('hex');

  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);

  AUTHENTICATION_REQUEST_CACHE.set(nonce, {
    redirect_uri: req.query.redirect_uri,
    state: req.query.state,
    code_challenge: req.query.code_challenge,
    upstream_code_challenge: codeChallenge,
    upstream_code_verifier: codeVerifier,
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

  if (!AUTHENTICATION_REQUEST_CACHE.has(nonce)) {
    res.send('no active login session');
  }

  const redirectUri = CLIENT.authorizationUrl({
    scope: 'openid email profile offline_access',
    code_challenge: AUTHENTICATION_REQUEST_CACHE.get(nonce).upstream_code_challenge,
    code_challenge_method: 'S256',
    state: nonce,
  });

  res.redirect(redirectUri);
}));

app.get('/qr-cb', runAsyncWrapper(async (req, res) => {
  const params = CLIENT.callbackParams(req);
  const nonce = params.state;

  if (AUTHENTICATED_NONCE_CACHE.has(nonce)) {
    res.send('Session already started');
    return;
  }
  if (!AUTHENTICATION_REQUEST_CACHE.has(nonce)) {
    res.send('No authorization session for this code is currently active');
    return;
  }

  const tokenSet = await CLIENT.callback(`${FRONTEND_URL}/qr-cb`, params, {
    code_verifier: AUTHENTICATION_REQUEST_CACHE.get(nonce).upstream_code_verifier,
    state: nonce,
    response_type: 'code',
  });
  console.log('received and validated tokens %j', tokenSet);
  console.log('validated ID Token claims %j', tokenSet.claims());

  AUTHENTICATED_NONCE_CACHE.set(nonce, {
    refresh_token: tokenSet.refresh_token,
    code_challenge: AUTHENTICATION_REQUEST_CACHE.get(nonce).code_challenge,
    id_token: tokenSet.id_token,
  });

  const userinfo = await CLIENT.userinfo(tokenSet.access_token);
  res.send(`User: ${userinfo.name}`);
}));

app.post('/token', runAsyncWrapper(async (req, res) => {
  const decodedCode = JSON.parse(decodeURIComponent(req.body.code));
  const authenticationRecord = AUTHENTICATED_NONCE_CACHE.get(decodedCode.nonce);

  if (authenticationRecord.code_challenge) {
    if (!req.body.code_verifier) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'missing code_verifier' });
      return;
    }
    let hash = crypto.createHash('sha256').update(req.body.code_verifier.toString('ascii')).digest('base64');
    hash = hash.split('=')[0].replace(/\+/g, '-').replace(/\//g, '_');

    if (hash !== authenticationRecord.code_challenge) {
      console.log(`bad challenge ${hash} !== ${authenticationRecord.code_challenge}`);
      res.status(400).json({ error: 'invalid_grant', error_description: 'Unable to verify code_challenge' });
      return;
    }
  }

  const idClaims = {
    iss: FRONTEND_URL,
    aud: req.body.client_id,
    sub: jwt.decode(authenticationRecord.id_token).sub,
  };

  const returnedTokenSet = {
    access_token: decodedCode.access_token,
    token_type: decodedCode.token_type,
    expires_in: decodedCode.expires_in,
    id_token: jwt.sign(idClaims, SERVER_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h', keyid: SERVER_JWK_KEY_ID }),
  };

  res.json(returnedTokenSet);
}));

app.get('/userinfo', runAsyncWrapper(async (req, res) => {
  const userinfo = await CLIENT.userinfo(req.token);
  res.json(userinfo);
}));

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

  const requestInfo = AUTHENTICATION_REQUEST_CACHE.take(nonce);

  try {
    const code = encodeURIComponent(`${JSON.stringify(await refreshTokens(nonce))}`);
    res.cookie('session', `qr_${nonce}`);
    res.redirect(`${requestInfo.redirect_uri}?state=${requestInfo.state}&session_state=qr_${nonce}&code=${code}`);
  } catch (error) {
    AUTHENTICATED_NONCE_CACHE.del(nonce);
    console.log('unable to refresh token in qr callback');
    res.redirect(`${requestInfo.redirect_uri}?error=invalid_request&state=${requestInfo.state}`);
  }
}));

app.get('/certs', (req, res) => {
  const keys = [{
    n: SERVER_JWK.n,
    e: SERVER_JWK.e,
    kid: SERVER_JWK_KEY_ID,
    kty: SERVER_JWK.kty,
    alg: 'RS256',
    use: 'sig',
  }];

  res.json(keys);
});

app.get('/check_session_iframe.html', (req, res) => {
  res.render('check_session_iframe');
});

app.get('/end_session', runAsyncWrapper(async (req, res) => {
  const { session } = req.cookies;
  const nonce = session.substring(3);

  if (AUTHENTICATED_NONCE_CACHE.has(nonce)) {
    try {
      await CLIENT.revoke(AUTHENTICATED_NONCE_CACHE.get(nonce).refresh_token);
    } catch (error) {
      console.log(error);
    }
  }

  AUTHENTICATION_REQUEST_CACHE.del(nonce);
  AUTHENTICATED_NONCE_CACHE.del(nonce);

  res.clearCookie('session');
  res.redirect(req.query.post_logout_redirect_uri);
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
