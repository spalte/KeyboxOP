FROM node:lts-alpine
ENV NODE_ENV=production
ENV LISTEN_ADDRESS=0.0.0.0

EXPOSE 8080
WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]
RUN npm install --production

COPY ["server.js", "./"]
COPY ["public/", "./public/"]
COPY ["views/", "./views/"]

CMD [ "node", "server.js" ]
