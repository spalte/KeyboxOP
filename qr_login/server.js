const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
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

const SECRET_KEY = 'bQeShVmYq3t6w9z$C&F)J@NcRfUjWnZr';

var refreshCache = new NodeCache({ stdTTL: 60 * 60 * 2 });

const static = express.static(path.join(__dirname, 'public'));
app.use(static);
app.use(nocache());
app.use(cookieParser(SECRET_KEY));
app.use(cookieEncrypter(SECRET_KEY));

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

    const tokenSet = await client.callback('http://127.0.0.1:8078/cb', params, { 
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
    if (credentials && credentials.name === "keybox_op" && credentials.pass === "pass") {
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
    const authority = await Issuer.discover('http://127.0.0.1:8075/auth/realms/YCC');
    console.log('Discovered authority %s %O', authority.issuer, authority.metadata);

    client = new authority.Client({
      client_id: 'qr_login',
      client_secret: '9f43f185-8965-402f-b7b8-130bb04d616b',
      redirect_uris: ['http://127.0.0.1:8078/cb'],
      response_types: ['code'],
    });
    
    //start our server
    server.listen(8078, '127.0.0.1', () => {
        console.log(`Server started on port ${server.address().port} :)`);
    });
})();

  