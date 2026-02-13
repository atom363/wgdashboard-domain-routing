ARG VERSION=latest
FROM ghcr.io/wgdashboard/wgdashboard:${VERSION}

RUN apk update && \
    apk add --no-cache ipset
