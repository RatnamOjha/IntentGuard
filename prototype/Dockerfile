FROM node:24.17.0-bookworm-slim AS build

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN corepack pnpm@11.24.0 install --frozen-lockfile
COPY . .
ARG NEXT_PUBLIC_INTENTGUARD_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_INTENTGUARD_API_URL=$NEXT_PUBLIC_INTENTGUARD_API_URL
RUN corepack pnpm@11.24.0 build

FROM node:24.17.0-bookworm-slim AS runtime

ENV NODE_ENV=production \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH
WORKDIR /app
RUN corepack enable \
    && groupadd --system intentguard \
    && useradd --system --gid intentguard --home-dir /app intentguard
COPY --from=build --chown=intentguard:intentguard /app/package.json /app/pnpm-lock.yaml /app/pnpm-workspace.yaml ./
COPY --from=build --chown=intentguard:intentguard /app/node_modules ./node_modules
COPY --from=build --chown=intentguard:intentguard /app/dist ./dist
USER intentguard
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["corepack", "pnpm@11.24.0", "start"]
