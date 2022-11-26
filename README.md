# HTTP JWKS forward auth
http-jwks-forward-auth is small forward authentication service that implements JWKS & JWT based authentication 
and access control. Original intended usage is with reverse proxies/api gateways such as traefik, allowing authentication & 
authorization to be done in front of microservices in one place.

## Behavior

The service contains JWKS url that is used for retrieving JWT keys which are then used for validating incoming JWT 
bearer tokens. Invalid or missing tokens result in HTTP 401 or 403 response. Valid authentication and authorization check result in HTTP 200 response.
On valid token the HTTP response populates HTTP headers `X-Forwarded-User` which contains `sub` field from the JWT
and field `X-Forwarded-Roles` which contains comma separated values from the JWT `scope` field.

## Access control

Access control consists of URI prefixes and allowed HTTP methods and scopes that can access the requested endpoint.
 The path prefixes are sorted by their length in descending order and first prefix that matches is used. 
This behavior allows to define more fine grained subpath access control.

Note that omitting scopes or allowed http methods results in those not being validated. Omitting scopes still results in 
validating the JWT itself so authentication is still present but no claims based authorization is done.

## Configuration

By default the service looks for configuration file `config.yaml` in the same directory. The path of the config  file 
can be overriden with environment variable `CONFIG_PATH`

While running the service checks for changes in the config file on 5s interval and if changes are detected the configs are reloaded.
If parsing of the config file results in errors then it is not loaded and old one is used. This functionality allows the 
access control definitions to be updated during runtime without having to restart the service.

```yaml
jwt:
  jwks_url: http://localhost/.well-known/jwks.json
  issuer: http://localhost
paths:
- path: /whoami/asd
  scopes:
    - test_scope
  methods:
    - GET
- path: /
```

## Building

`cd http-forward-auth && go build` will build the application.

`docker build -tag http-forward-auth:latest .` can be used to build a docker container based on google's 'distroless' containers.

Example usage of building and running the service with traefik and config.yaml in the same directory using docker-compose can be done as the following:

```yaml
version: "3.3"

services:

  traefik:
    image: "traefik:v2.9"
    container_name: "traefik"
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:8081"
    ports:
      - "80:80"
      - "8080:8080"
      - "8081:8081"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"

  whoami:
    image: "traefik/whoami"
    container_name: "simple-service"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=PathPrefix(`/whoami`)"
      - "traefik.http.routers.whoami.entrypoints=web"
      - "traefik.http.routers.whoami.middlewares=traefik-http-forward-auth"

  traefik-forward-auth:
    container_name: "traefik-http-forward-auth"
    build: .
    volumes:
      - "./config.yaml:/config.yaml:ro" # Config file needs to be in the same directory
    environment:
      CONFIG_PATH: "/config.yaml"
      GIN_MODE: release
    labels:
      - "traefik.enable=true"
      - "traefik.http.middlewares.traefik-http-forward-auth.forwardauth.address=http://traefik-http-forward-auth:8080"
      - "traefik.http.middlewares.traefik-http-forward-auth.forwardauth.authRequestHeaders=Authorization" # Pass Authorization header for the authentication service
      - "traefik.http.middlewares.traefik-http-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User, X-Forwarded-Roles" # Forward the returned user and role headers
```

When running this can be tested on http://localhost:8081/whoami/