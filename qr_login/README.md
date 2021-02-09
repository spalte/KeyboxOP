# QR Login Server

Server component of the QR login mechanism.

## Environment Variables

`FRONTEND_URL` *Required* The base URL at which the server will be accessible.

`OIDC_AUTHORITY` *Required* The OIDC Provider that will be used.

`OIDC_CLIENT_ID` *Required* The Client ID that will be used.

`OIDC_CLIENT_SECRET` *Required* The Client Secret that will be used.

`KEYBOX_OP_NAME` *Required* Name passed by the Keybox OP in basic auth.

`KEYBOX_OP_PASSWORD` *Required* Password passed by the Keybox OP in basic auth.

`PORT` *Optional* Port on which the server will listen. Default is 8080.

`LISTEN_ADDRESS` *Optional* Address on which the server will listen. Default is 0.0.0.0.

`COOKIE_SECRET_KEY` *Optional* Secret used to sign and encrypt cookies. Default is to generate a new secret at startup.