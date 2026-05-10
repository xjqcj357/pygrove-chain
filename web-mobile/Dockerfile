# Mobile / browser wallet served at https://str4w.com/.
# Static-only: this container ships the SPA. TLS termination + RPC reverse
# proxy live one tier up in the box's main nginx (akiyafinder-frontend).

FROM nginx:alpine

# Replace the default site with our config.
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Drop the SPA. Single static file; no build step. ESM imports load
# noble-ed25519 / noble-hashes / scure-base from esm.sh on first visit.
COPY index.html /usr/share/nginx/html/index.html

# Block explorer at /explorer/ — same origin as the wallet so the chain
# selector survives across both pages via shared localStorage.
COPY explorer.html /usr/share/nginx/html/explorer/index.html

# Emission / chain-info page at /info/ with SVG chart of actual vs planned
# emission curves, 1h–6m zoom buttons, key KPIs.
COPY info.html /usr/share/nginx/html/info/index.html

EXPOSE 80
