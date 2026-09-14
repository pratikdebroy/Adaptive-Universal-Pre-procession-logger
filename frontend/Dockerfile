# Build stage
FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Serve stage
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html

# Nginx config for SPA routing and API proxy
RUN echo 'server { \
    listen 3000; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html index.htm; \
        try_files $uri $uri/ /index.html; \
    } \
    location /api/ { \
        proxy_pass http://backend:8000/api/; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
