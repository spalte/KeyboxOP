FROM node:lts-alpine
ENV NODE_ENV=production
ENV LISTEN_ADDRESS=0.0.0.0

EXPOSE 8080
WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]
RUN npm install --production

COPY ["server.js", "oidc-client.min.js", "vanillajs.png", "./"]
COPY ["public/", "./public/"]

CMD [ "node", "server.js" ]
