FROM ghcr.io/nginx/nginx-unprivileged:1.31.1-alpine3.23@sha256:cc300bd2e8776708a8c2c8686a74f06eadf221c5ce01e85d0e821955d7a730ab

COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=nginx:nginx index.html styles.css app.js /usr/share/nginx/html/

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/ || exit 1
