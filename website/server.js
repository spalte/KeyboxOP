var express = require('express');
var path = require('path');
var app = express();
const nocache = require('nocache');

var static = express.static(path.join(__dirname, 'public'));
app.use(static);
app.use(nocache());

app.get("/oidc-client.js", function(req, res){
    res.sendFile(path.join(__dirname, 'oidc-client.min.js'));
});

app.get("/vanillajs.png", function(req, res){
    res.sendFile(path.join(__dirname, 'vanillajs.png'));
});

app.listen(8080, () => {
    console.log('OIDC Redirect listening');
});
  