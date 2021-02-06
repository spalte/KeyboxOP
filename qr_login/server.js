const express = require('express');
const path = require('path');
const app = express();
const nocache = require('nocache');
const mustacheExpress = require('mustache-express');
const cookieParser = require("cookie-parser");
const cookieEncrypter = require('cookie-encrypter')

const { Issuer, generators } = require('openid-client');

const SECRET_KEY = 'bQeShVmYq3t6w9z$C&F)J@NcRfUjWnZr';


const static = express.static(path.join(__dirname, 'public'));
app.use(static);
app.use(nocache());
app.use(cookieParser(SECRET_KEY));
app.use(cookieEncrypter(SECRET_KEY));

app.use(cookieParser());

app.set('views', './views');
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

app.get('/login', (req, res) => {
    const modulus = req.query.modulus;

    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);

    const redirectUri = client.authorizationUrl({
        scope: 'openid email profile',
        // resource: 'https://my.api.example.com/resource/32178',
        code_challenge,
        code_challenge_method: 'S256',
    });

    res.cookie('code_verifier', code_verifier, {
        signed: true,
        maxAge: 5000,
        httpOnly: true,
    });

    res.redirect(redirectUri);
});

app.get('/cb', runAsyncWrapper(async (req, res) => {
    const params = client.callbackParams(req);

    const code_verifier = req.signedCookies.code_verifier;

    const tokenSet = await client.callback('http://127.0.0.1:8078/cb', params, { code_verifier });
    console.log('received and validated tokens %j', tokenSet);
    console.log('validated ID Token claims %j', tokenSet.claims());
    
    const userinfo = await client.userinfo(tokenSet.access_token);
    console.log('userinfo %j', userinfo);

    res.send("ok");
}));

(async function configureOIDC() {
    const authority = await Issuer.discover('http://127.0.0.1:8075/auth/realms/YCC');
    console.log('Discovered authority %s %O', authority.issuer, authority.metadata);

    client = new authority.Client({
      client_id: 'qr_login',
      client_secret: '9f43f185-8965-402f-b7b8-130bb04d616b',
      redirect_uris: ['http://127.0.0.1:8078/cb'],
      response_types: ['code'],
    });
    
    app.listen(8078, '127.0.0.1', () => {
        console.log('OIDC Redirect listening at http://127.0.0.1:8078');
    });
    
})();

  