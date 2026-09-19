FROM node:18-alpine AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
# Copy a custom nginx config to route /api to the backend
RUN echo "server { listen 80; location / { root /usr/share/nginx/html; try_files `$uri `$uri/ /index.html; } location /api/ { proxy_pass http://backend:8000/api/; proxy_set_header Host `$host; proxy_set_header X-Real-IP `$remote_addr; } }" > /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
