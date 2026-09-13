# The front-end image: static assets behind nginx, with no knowledge of the gateway.
#
# Two things are deliberate:
#
# 1. **There is no `/v1` proxy here.** An earlier console reverse-proxied the API through its own
#    origin, which made "the console" and "the API" one deployable unit. This image serves files
#    and nothing else, so it can sit behind any gateway, on any host, including a CDN.
# 2. **The API address is written at start-up, not baked in.** `docker-entrypoint.d/` runs before
#    nginx and writes `/config.js` from `AEGIS_API_BASE`, so one image serves every deployment.
#    `VITE_API_BASE` still exists for `npm run dev`, but a production image must not need a
#    rebuild to be pointed somewhere else.

FROM node:22-alpine AS build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /build/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend/docker-entrypoint.d/10-api-base.sh /docker-entrypoint.d/10-api-base.sh
RUN chmod 0755 /docker-entrypoint.d/10-api-base.sh

EXPOSE 8102
