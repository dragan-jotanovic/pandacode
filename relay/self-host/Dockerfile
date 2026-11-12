# PandaCode Connect relay, run locally with `wrangler dev` (workerd) instead of on Cloudflare.
# Build from the relay folder:  docker build -f self-host/Dockerfile .
FROM node:22-bookworm-slim

ARG WRANGLER_VERSION=4
ENV WRANGLER_SEND_METRICS=false \
    WRANGLER_HOME=/tmp/wrangler-home \
    CI=1

# workerd needs a system CA bundle, and the relay calls github.com to verify sign-ins.
# The Worker's own dependencies are only types, so only wrangler is installed.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && npm install --prefix /opt/wrangler --no-audit --no-fund wrangler@${WRANGLER_VERSION} \
 && mkdir -p /app /data && chown -R node:node /app /data

WORKDIR /app
COPY --chown=node:node src ./src
COPY --chown=node:node tsconfig.json ./
COPY --chown=node:node self-host ./self-host
RUN chmod +x self-host/entrypoint.sh

USER node
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["/app/self-host/entrypoint.sh"]
