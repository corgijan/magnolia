# syntax=docker/dockerfile:1

FROM node:20-slim AS builder
WORKDIR /app

COPY package.json package-lock.json ./
# Cache-mounted npm cache -- persists across builds independent of layer
# caching, so even a package-lock.json change (which busts this layer)
# only re-downloads packages that actually changed instead of every
# dependency from the registry.
RUN --mount=type=cache,target=/root/.npm \
    npm ci

COPY . .
# CRA's build (via babel-loader) writes its own cache under
# node_modules/.cache -- cache-mounting it means an unchanged file skips
# re-transpilation even though the whole `COPY . .` layer above is
# invalidated by any source change.
RUN --mount=type=cache,target=/app/node_modules/.cache \
    npm run build

FROM nginx:1.27-alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
