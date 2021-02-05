# Keybox OP

## Environment variables

`ISSUER` *Optional* Can be set to specify at what URL the service will be running (ex. `http://127.0.0.1:8085`). By default an attempt will be made to derive the issuer from the request.

`LISTEN_PORT` *Optional* Can be used to set what port will be used. Default is 80.

`LISTEN_ADDRESS` *Optional* IP address to bind. Set to the unspecified address (`0.0.0.0`) to bind all addresses. Default is `127.0.0.1`. The Docker image default is `0.0.0.0`.

`SERVER_PRIVATE_KEY_FILE` *Optional* Can be specified to provide the key the server will use to sign the returned `id_token`. If this is not specified, a new private key will be generated at startup. The commented out values in the `docker-compose.yml` rely on the presence of a file that must be created and named, `server_private_key.pem`.

`SERVER_PRIVATE_KEY` Can be used to specify the server private key directly.
