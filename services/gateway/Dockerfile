FROM node:20-alpine

WORKDIR /app
COPY services/gateway/package*.json ./
RUN npm install --omit=dev

COPY services/gateway/src/ ./src/

EXPOSE 4000
ENV PORT=4000
ENV AEGIS_ENGINE_URL=http://engine:8080

CMD ["node", "src/index.js"]
