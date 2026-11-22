# 1) build do Angular  2) nginx serve os arquivos e encaminha /api para o backend
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npx ng build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/front-end/browser /usr/share/nginx/html
EXPOSE 80
