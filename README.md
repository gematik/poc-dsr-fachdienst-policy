# DSR Fachdienst OPA / policies

> **Note:** `opa` and `docker` must be installed locally

## Build OPA bundle

```console
opa build -b src/bundle/ -o dsr-fachdienst-policy-bundle.tar.gz
```

## Configure (generate mandatory keys)

```shell script
./configure.sh
```

set your opa-user password in file nginx/.htpasswd

### OR: Build & Sign OPA bundle

```console
opa build -b src/bundle/ -o dsr-fachdienst-policy-bundle.tar.gz --signing-key sign/bundle_sign_prk.pem --signing-alg ES256 --claims-file sign/claims.json
```

#### ops sign command to create .signatures.json

```console
opa sign --signing-key sign/bundle_sign_prk.pem --signing-alg ES256 -b src/bundle/
```

### Inspect the OPA bundle

```console
opa inspect dsr-fachdienst-policy-bundle.tar.gz
```

### Test

```console
opa test -v src -f pretty --explain full
```

### Test with Coverage

```console
opa test -v src -f pretty --explain full --coverage --format=json
```

---

## Build the dsr/opa-bundle-server container image (based on NGINX)

```console
docker build -t dsr/opa-bundle-server .
```

### Run dsr/opa-bundle-server

```console
docker run -p 8787:80 dsr/opa-bundle-server
```

### Verify the dsr/opa-bundle-server

```console
curl --location 'http://localhost:8787/opa-bundle/dsr-fachdienst-policy-bundle.tar.gz' --header 'Authorization: Basic b3BhLXVzZXI6b3BhLXNlY3JldA==' -o dsr-fachdienst-policy-bundle.tar.gz
```

---

## Run dsr/opa-bundle-server and a OPA server instance (locally)

```console
docker compose -f docker-compose-deployLocal-OPA.yml up
```