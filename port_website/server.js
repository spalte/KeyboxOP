var express = require('express');
var path = require('path');
var app = express();
const nocache = require('nocache');
const mustacheExpress = require('mustache-express');

const {
  FRONTEND_URL,
  OIDC_AUTHORITY,
  OIDC_CLIENT_ID,
} = process.env;

let {
  PORT,
  LISTEN_ADDRESS,
} = process.env;
  
PORT = PORT || 8080;
LISTEN_ADDRESS = LISTEN_ADDRESS || '0.0.0.0';
  
var static = express.static(path.join(__dirname, 'public'));
app.use(static);
app.use(nocache());
app.set('views', path.join(__dirname, 'views'));
app.engine('html', mustacheExpress());
app.set('view engine', 'html');

app.get('/', (req, res) => {
  res.render('index', {
    frontend_url: FRONTEND_URL, 
    oidc_authority: OIDC_AUTHORITY,
    oidc_client_id: OIDC_CLIENT_ID,
  });
});
  
app.listen(PORT, LISTEN_ADDRESS, () => {
    console.log('OIDC Redirect listening');
});
  