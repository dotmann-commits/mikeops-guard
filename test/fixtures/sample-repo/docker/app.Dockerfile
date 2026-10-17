FROM node:latest
RUN apt-get update && apt-get install -y curl
ADD . /app
WORKDIR /app
RUN npm install
CMD node server.js
