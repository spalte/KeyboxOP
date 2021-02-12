var express = require('express');
var path = require('path');
var app = express();
const nocache = require('nocache');

let {
  PORT,
  LISTEN_ADDRESS,
} = process.env;
  
PORT = PORT || 8080;
LISTEN_ADDRESS = LISTEN_ADDRESS || '0.0.0.0';
  
var static = express.static(path.join(__dirname, 'public'));
app.use(static);
app.use(nocache());

app.get("/oidc-client.js", function(req, res){
    res.sendFile(path.join(__dirname, 'oidc-client.min.js'));
});

app.get("/vanillajs.png", function(req, res){
    res.sendFile(path.join(__dirname, 'vanillajs.png'));
});

app.listen(PORT, LISTEN_ADDRESS, () => {
    console.log('OIDC Redirect listening');
});
  