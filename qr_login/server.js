const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');
const app = express();
const nocache = require('nocache');
const mustacheExpress = require('mustache-express');
const cookieParser = require("cookie-parser");
const cookieEncrypter = require('cookie-encrypter');
const auth = require('basic-auth');
const NodeCache = require("node-cache");
const jwk2pem = require('pem-jwk').jwk2pem
const NodeRSA = require('node-rsa');
const sleep = require('sleep-promise');
const { Issuer, generators } = require('openid-client');
const { exit } = require('process');

const refreshCache = new NodeCache({ stdTTL: 60 * 60 * 2 });

const {
    FRONTEND_URL,
    OIDC_AUTHORITY,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    KEYBOX_OP_NAME,
    KEYBOX_OP_PASSWORD,
} = process.env;

if (!FRONTEND_URL) {
    console.log('Missing FRONTEND_URL');
    exit(1);
}

if (!OIDC_AUTHORITY) {
    console.log('Missing OIDC_AUTHORITY');
    exit(1);
}

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

const static = express.static(path.join(__dirname, 'public'));
app.use(static);
app.use(nocache());
app.use(cookieParser(COOKIE_SECRET_KEY));
app.use(cookieEncrypter(COOKIE_SECRET_KEY));

app.use(cookieParser());

app.set('views', path.join(__dirname, 'views'));
app.engine('html', mustacheExpress());
app.set('view engine', 'html');

let client;

// will no longer be needed in Express.js 5
function runAsyncWrapper(callback) {
    return (req, res, next) => {
      callback(req, res, next)
        .catch(next);
    };
  }

app.get('/login', runAsyncWrapper(async (req, res) => {
    const modulus = req.query.n;
    if (!modulus) {
        res.status(400).send('Missing modulus');
        return;
    }

    let wsAttributed = false;
    wss.clients.forEach(function each(client) {
        if (client.modulus === modulus) {
            wsAttributed = true;
        }
    });
    if (!wsAttributed) {
        await sleep(2000);
        wss.clients.forEach(function each(client) {
            if (client.modulus === modulus) {
                wsAttributed = true;
            }
        });    
    }
    if (!wsAttributed) {
        res.status(400).send('unknown session');
    }

    if (refreshCache.has(modulus)) {
        res.status(400).send('session already used');
    }

    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);

    const redirectUri = client.authorizationUrl({
        scope: 'openid email profile',
        code_challenge,
        code_challenge_method: 'S256',
        state: modulus,
    });

    res.cookie('code_verifier', code_verifier, {
        signed: true,
        maxAge: 1000 * 60 * 5,
        httpOnly: true,
    });

    res.redirect(redirectUri);
}));

app.get('/cb', runAsyncWrapper(async (req, res) => {
    const params = client.callbackParams(req);
    const modulus = params.state;
    const code_verifier = req.signedCookies.code_verifier;

    const tokenSet = await client.callback(`${FRONTEND_URL}/cb`, params, {
        code_verifier,
        state: modulus,
        response_type: 'code',
    });
    console.log('received and validated tokens %j', tokenSet);
    console.log('validated ID Token claims %j', tokenSet.claims());
    
    const userinfo = await client.userinfo(tokenSet.access_token);

    if (!refreshCache.has(modulus)) {
        refreshCache.set(modulus, tokenSet.refresh_token, tokenSet.refresh_expires_in);
    } else {
        client.revoke(tokenSet.refresh_token, 'refresh_token');
        res.status(400).send('session already used');
    }

    sendRefresh(modulus);
    res.render('callback.html', {
        modulus: modulus,
        name: userinfo.name,
    });
}));

app.get('/logout', runAsyncWrapper(async (req, res) => {
    const modulus = req.query.n;
    if (!modulus) {
        res.status(400).send('Missing modulus');
        return;
    }

    refreshCache.del(modulus);

    res.send('ok');
}));

  
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', function (request, socket, head) {
    console.log('Parsing session from request...');
  
    const credentials = auth(request);
    if (credentials && credentials.name === KEYBOX_OP_NAME && credentials.pass === KEYBOX_OP_PASSWORD) {
        wss.handleUpgrade(request, socket, head, function (ws) {
            wss.emit('connection', ws, request);
        });
    } else {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
    }
});

wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        if (message.toString().startsWith('modulus=')) {
            if (ws.modulus) {
                refreshCache.del(ws.modulus);
            }
            ws.modulus = message.toString().slice(8);
        } else if (message.toString() === 'refresh') {
            sendRefresh(ws.modulus);
        } else if (message.toString() === 'logout') {
            refreshCache.del(ws.modulus);
        }
    });
});

async function sendRefresh(modulus) {
    const refreshToken = refreshCache.get(modulus);

    if (!refreshToken) {
        return;
    }

    const tokenSet = await client.refresh(refreshToken);
    if (tokenSet.refresh_token) {
        refreshCache.set(modulus, tokenSet.refresh_token, tokenSet.refresh_expires_in);
    }

    const jwk = {
        n: modulus,
        kty: 'RSA',
        alg: 'RS256',
        e: 'AQAB',
    }

    const accessTokenSet = {
        access_token: tokenSet.access_token,
        expires_at: tokenSet.expires_at,
        token_type: tokenSet.token_type,
        scope: tokenSet.scope,
    }

    const pem = jwk2pem(jwk)
    const key = new NodeRSA(pem);
    const encrypted = key.encrypt(JSON.stringify(accessTokenSet), 'base64');

    wss.clients.forEach(function each(client) {
        if (client.readyState === WebSocket.OPEN && client.modulus === modulus) {
            client.send('encrypted_tokens=' + encrypted);
        }
    });
}

refreshCache.on( "del", function( modulus, refreshToken ){
    wss.clients.forEach(function each(client) {
        if (client.modulus === modulus) {
            client.modulus = undefined;
            if (client.readyState === WebSocket.OPEN) {
                client.send('logged_out');
            }
        }
    });
    client.revoke(refreshToken, 'refresh_token');
});

(async function configureOIDC() {
    const authority = await Issuer.discover(OIDC_AUTHORITY);
    console.log('Discovered authority %s %O', authority.issuer, authority.metadata);

    client = new authority.Client({
      client_id: OIDC_CLIENT_ID,
      client_secret: OIDC_CLIENT_SECRET,
      redirect_uris: [`${FRONTEND_URL}/cb`],
      response_types: ['code'],
    });
    
    //start our server
    server.listen(PORT, LISTEN_ADDRESS, () => {
        console.log(`Server started at ${server.address().address}:${server.address().port}`);
    });
})();

  