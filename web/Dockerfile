# Janet landing-page sidecar.
# Tiny: alpine + the janet package + 80 lines of Lisp.

FROM alpine:3.19

RUN apk add --no-cache janet

WORKDIR /app
COPY site.janet /app/site.janet

EXPOSE 8080
ENV PORT=8080

CMD ["janet", "/app/site.janet"]
