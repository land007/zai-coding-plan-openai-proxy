FROM rust:1.94-alpine AS builder

WORKDIR /app
RUN apk add --no-cache build-base musl-dev perl

COPY Cargo.toml Cargo.toml
COPY auth-callback-public.pem auth-callback-public.pem
COPY src src

RUN cargo build --release

FROM alpine:3.22

WORKDIR /app
RUN apk add --no-cache ca-certificates curl

COPY --from=builder /app/target/release/zai-coding-plan-openai-proxy /usr/local/bin/zai-coding-plan-openai-proxy

ENV HOST=0.0.0.0
ENV PORT=8787
ENV ZAI_CODING_PLAN_ENDPOINT=global

EXPOSE 8787

CMD ["zai-coding-plan-openai-proxy"]

# docker buildx build --platform linux/amd64,linux/arm64 -t land007/zai-coding-plan-openai-proxy:latest --push .
