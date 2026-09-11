# aegis-web: the console. Own image so front-end changes never rebuild a Python image.
#
# Two stages: Node builds the bundle, nginx serves it. The build stage is discarded, so the
# runtime image is nginx plus a few hundred kilobytes of static assets -- there is no Node,
# no npm, and nothing to execute at runtime.
#
# Node is pinned to the major version the repository already asserts elsewhere, and to alpine
# because the build stage only needs to run `npm ci` and `vite build`: no native modules, no
# glibc-specific tooling. The runtime stage is nginx-alpine for the same reason -- the smaller
# the image, the less there is to keep patched. An unpinned base image is how a front-end build
# starts failing on a Tuesday for reasons unrelated to the code.

FROM node:22-alpine AS build

WORKDIR /build

# Dependency manifests first: `npm ci` is the slow step and it must not be invalidated by a
# change to a component. `package-lock.json` is what makes the install reproducible, so it is
# copied explicitly -- and it is committed, because an unpinned install is not reproducible.
COPY services/web/package.json services/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Then the sources. `tsc --noEmit` runs inside the build script, so a type error fails the
# image rather than shipping a bundle that will throw in a browser.
COPY services/web/ ./
RUN npm run build


FROM nginx:1.27-alpine

# The console is a static file server plus a proxy. No dynamic configuration, no modules.
COPY --from=build /build/dist /usr/share/nginx/html
COPY services/web/nginx.conf /etc/nginx/conf.d/default.conf

# Advertised port inside the compose network. The host port mapping is the compose file's
# decision, and it is the only one of the two that can expose anything.
EXPOSE 8102

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=5s \
    CMD wget -q -O /dev/null http://127.0.0.1:8102/healthz || exit 1
