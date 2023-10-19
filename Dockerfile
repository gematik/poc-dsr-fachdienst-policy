# Build-Container
FROM openpolicyagent/opa:latest-debug AS builder
# opa:latest-debug: this variant includes a shell and is based on the lightweight distroless images.

WORKDIR /app

COPY src/bundle .
COPY sign ./sign

# OPA build & sign bundle
RUN opa build -b . -o dsr-fachdienst-policy-bundle.tar.gz \
    --signing-key sign/bundle_sign_prk.pem \
    --signing-alg ES256 \
    --claims-file sign/claims.json

# Inspect the bundle, just for information
RUN opa inspect -a dsr-fachdienst-policy-bundle.tar.gz

# NGINX OPA Bundle Server - Container
FROM nginx:1.25.2-alpine

# The STOPSIGNAL instruction sets the system call signal that will be sent to the container to exit
# SIGTERM = 15 - https://de.wikipedia.org/wiki/Signal_(Unix)
STOPSIGNAL SIGTERM

# Create a directory for the OPA bundle in the container
RUN mkdir /usr/share/nginx/html/opa-bundle

# Copy OPA-Bundle to NGINX
COPY --from=builder /app/dsr-fachdienst-policy-bundle.tar.gz /usr/share/nginx/html/opa-bundle/

# Copy nginx.conf & .htpasswd
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/.htpasswd /etc/pwd/.htpasswd

CMD ["nginx", "-g", "daemon off;"]

EXPOSE 80

ARG COMMIT_HASH
ARG VERSION

# Define Labels
LABEL de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION \
      de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="DSR OPA Bundle Server" \
      de.gematik.git-repo-name="https://gitlab.prod.ccs.gematik.solutions/git/poc/sicherheit/devicesecurityrating/dsr-fachdienst-policy.git"