# Build-Container
FROM openpolicyagent/opa:latest-debug AS builder
# This variant includes a shell and is based on the lightweight distroless images.

WORKDIR /app

COPY src/bundle .
COPY sign ./sign

# OPA build & sign bundle
RUN opa build -b . -o dsr-fachdienst-policy-bundle.tar.gz \
    --signing-key sign/bundle_sign_prk.pem \
    --signing-alg ES256 \
    --claims-file sign/claims.json

# Insepct the bundle
RUN opa inspect -a dsr-fachdienst-policy-bundle.tar.gz

# OPA Server-Container
FROM openpolicyagent/opa:latest

# The STOPSIGNAL instruction sets the system call signal that will be sent to the container to exit
# SIGTERM = 15 - https://de.wikipedia.org/wiki/Signal_(Unix)
STOPSIGNAL SIGTERM

WORKDIR /app

COPY --from=builder /app/sign/bundle_sign_puk.pem .
COPY --from=builder /app/dsr-fachdienst-policy-bundle.tar.gz .

# run OPA-Server with dsr-fachdienst-policy-bundle.tar.gz
CMD ["run", "--server", "--bundle", "dsr-fachdienst-policy-bundle.tar.gz", "--log-format", "text", "--signing-alg", "ES256", "--verification-key", "bundle_sign_puk.pem"]

EXPOSE 8181

ARG COMMIT_HASH
ARG VERSION

# Define Labels
LABEL de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION \
      de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="DSR FD Open Policy Agent (OPA)" \
      de.gematik.git-repo-name="https://.../dsr-fachdienst-policy.git"
