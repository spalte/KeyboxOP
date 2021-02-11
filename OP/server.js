/* eslint-disable no-console */
/* eslint-disable no-use-before-define */
const fs = require('fs');
const path = require('path');
// const axios = require('axios');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const nocache = require('nocache');
const mustacheExpress = require('mustache-express');
const WebSocket = require('ws');

const app = express();

app.use(cors({
  allowedHeaders: 'Authorization',
  methods: 'HEAD,GET,POST',
}));
app.use(express.urlencoded());
app.use(nocache());
app.set('json spaces', 2);
app.set('etag', false);
app.set('x-powered-by', false);
app.set('views', path.join(__dirname, 'views'));
app.engine('html', mustacheExpress());
app.set('view engine', 'html');

const {
  SERVER_PRIVATE_KEY_FILE,
  ISSUER,
} = process.env;

let {
  SERVER_PRIVATE_KEY,
} = process.env;

if (SERVER_PRIVATE_KEY_FILE) {
  SERVER_PRIVATE_KEY = fs.readFileSync(SERVER_PRIVATE_KEY_FILE, 'ascii');
}
if (!SERVER_PRIVATE_KEY) {
  SERVER_PRIVATE_KEY = new NodeRSA().generateKeyPair().exportKey('pkcs1-private-pem');
}
const SERVER_JWK = pem2jwk(SERVER_PRIVATE_KEY);
const SERVER_JWK_KEY_ID = '0';

const LISTEN_PORT = Number(process.env.LISTEN_PORT || 80);
const LISTEN_ADDRESS = process.env.LISTEN_ADDRESS || '127.0.0.1';

const REFRESH_TOKEN = crypto.createHash('sha256').update([
  'SERVER_PRIVATE_KEY',
  'LISTEN_PORT',
].join()).digest('base64');

const ws = new WebSocket('wss://keybox_op:KLN6N3O8Or0BuFTCwzjgLDqleTocbp@ycc-qr-login.naturalimage.ch');

// will no longer be needed in Express.js 5
function runAsyncWrapper(callback) {
  return (req, res, next) => {
    callback(req, res, next)
      .catch(next);
  };
}

async function fetchAccessToken() {
  return null;
}

let CURRENT_KEY;

function rotateCurrentKey() {
  CURRENT_KEY = new NodeRSA().generateKeyPair(128).exportKey('pkcs1-private-pem');
}

function currentModulus() {
  const jwk = pem2jwk(CURRENT_KEY);
  return jwk.n;
}

app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = getIssuer(req);

  const configuration = {
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    introspection_endpoint: `${issuer}/introspect`,
    jwks_uri: `${issuer}/certs`,
    check_session_iframe: `${issuer}/check_session_iframe.html`,
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

app.get('/auth', (req, res) => {
  // const redirectUri = new URL(req.query.redirect_uri);

  rotateCurrentKey();
  const n = currentModulus();
  ws.send(`modulus=${n}`);

  const urlString = `https://ycc-qr-login.naturalimage.ch/login?n=${n}`;
  const encodedString = encodeURIComponent(urlString);

  res.render('auth', { login_url: encodedString, key_length: n.length });
});

app.post('/token', runAsyncWrapper(async (req, res) => {
  const issuer = getIssuer(req);

  if (req.body.grant_type === 'refresh_token' && req.body.refresh_token !== REFRESH_TOKEN) {
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  const idClaims = {
    iss: issuer,
    aud: req.body.client_id,
  };

  let accessTokenData;
  try {
    accessTokenData = await fetchAccessToken();
  } catch (error) {
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
      return;
    }
    throw error;
  }

  const responseBody = {
    access_token: accessTokenData.access_token,
    token_type: accessTokenData.token_type,
    expires_in: accessTokenData.expires_in,
    ...(req.body.grant_type === 'authorization_code' && {
      refresh_token: REFRESH_TOKEN,
      id_token: jwt.sign(idClaims, SERVER_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h', keyid: SERVER_JWK_KEY_ID }),
    }),
  };

  res.json(responseBody);
}));

app.get('/userinfo', (req, res) => {
  const userinfo = {};

  res.json(userinfo);
});

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

app.post('/introspect', runAsyncWrapper(async (req, res) => {
  let introspectBody;
  const { token } = req.body;
  let myToken;
  try {
    myToken = jwt.verify(token, SERVER_PRIVATE_KEY, { algorithms: ['RS256'] });
  // eslint-disable-next-line no-empty
  } catch (err) { }

  if (myToken) {
    introspectBody = myToken;
    introspectBody.token_type = 'id_token';
  } else if (token === REFRESH_TOKEN) {
    introspectBody = {
      active: true,
      token_type: 'refresh_token',
    };
  } else {
    introspectBody = {
      active: true,
      token_type: 'access_token',
    };
  }

  if (introspectBody.scope) {
    introspectBody.scope = introspectBody.scope.replace(/https:\/\/www\.googleapis\.com\/auth\/userinfo\./g, '');
    introspectBody.scope = introspectBody.scope.concat(' offline_access');
  }

  res.json(introspectBody);
}));

app.get('/check_session_iframe.html', (req, res) => {
  res.render('check_session_iframe', { issuer: getIssuer(req) });
});

app.get('/deadend', (req, res) => {
  res.json(req.query);
});

function getIssuer(request) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  let issuer = ISSUER;
  if (!issuer) {
    if (request.headers['x-forwarded-host']) {
      issuer = `${request.headers['x-forwarded-proto'] || 'http'}://${request.headers['x-forwarded-host']}`;
    } else {
      issuer = url.origin;
    }
  }
  return issuer;
}

app.listen(LISTEN_PORT, LISTEN_ADDRESS || '127.0.0.1', () => {
  console.log(`OIDC Redirect listening at http://${LISTEN_ADDRESS}:${LISTEN_PORT}`);
});
