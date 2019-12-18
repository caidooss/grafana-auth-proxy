# Grafana Auth Proxy
[![CI](https://github.com/caido/grafana-auth-proxy/workflows/CI/badge.svg)](https://github.com/caido/grafana-auth-proxy/actions?query=workflow%3ACI)
[![Maintainability](https://api.codeclimate.com/v1/badges/0bad80ade3fec5f8c33f/maintainability)](https://codeclimate.com/github/caido/grafana-auth-proxy/maintainability)
[![Docker Pulls](https://img.shields.io/docker/pulls/caido/grafana-auth-proxy)](https://hub.docker.com/repository/docker/caido/grafana-auth-proxy)
[![Docker Analaysis](https://images.microbadger.com/badges/image/caido/grafana-auth-proxy.svg)](https://microbadger.com/images/caido/grafana-auth-proxy)

This is simple, lightweight and performant reverse authentication proxy for Grafana using JWT tokens.
It was originally designed to be more flexible than the [documented solution](https://grafana.com/docs/grafana/latest/auth/auth-proxy/) based on Apache.
Using this solution, the user will **not** be presented with a login screen and will arrive directly in its dashboards.
This is thus ideal when you want to embed Grafana in another application.

This proxy can accept tokens from a cookie or an header. We use a cookie in production, because it is the easiest way to deploy a multi-tenant Grafana without patching the frontend.
Note that the proxy does **NOT** handle the creation of the tokens and cookies (which can be vulnerable to CSRF), please be sure to know what you are doing before deploying this solution in production.

## Grafana
Before using this proxy, you need to setup grafana correctly. A few parameters are required:
```bash
GF_AUTH_PROXY_ENABLED=true                  # Enable authentication via a proxy
GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER    # Header that grafana will expect (do not change)
GF_AUTH_PROXY_HEADER_PROPERTY=email         # Either email or username depending on what will be in the token
GF_AUTH_PROXY_AUTO_SIGN_UP=false            # In case of a multi-tenant system, make sure to disable auto sign up
```

## Usage
We recommend that you start from the provided Docker image.

The proxy requires a couple of parameters to work. You can either provide them using environment variable (preferred) or using program flags.
The proxy will load a `.env` file in the same directory.
```bash
PROXY_SERVED_URL=http://localhost:3000                                  # Grafana URL (usually this will not change)
PROXY_PORT=5000                                                         # Proxy on which the proxy will listen to (all interfaces)
PROXY_COOKIE_AUTH=true                                                  # Enable Cookie authentication
PROXY_COOKIE=MyAccessToken                                              # The name of the cookie containing the JWT token
PROXY_HEADER_AUTH=true                                                  # Enable Header authentication
PROXY_HEADER=Authorization                                              # (Optional) The name of the header containing the JWT token
PROXY_HEADER_PREFIX=Bearer                                              # (Optional) Prefix of the header value to expect
PROXY_JWK_FETCH_URL=https://testing.auth0.com/.well-known/jwks.json     # URL to retrieve JWKs from
PROXY_JWT_ALGORITHMS=RS256,HS256                                        # (Optional) Valid algorithms for the signature. Default=RS256
PROXY_JWT_ISSUER=https://testing.auth0.com/                             # The issuer of the JWT token
PROXY_JWT_AUDIENCE=https://api.testing.io/                              # The audience of the JWT token
PROXY_JWT_GRAFANA_CLAIM=https://testing.io/email                        # The claim to use in the token to authenticate the user (email or username)
```

You can then do `docker run -p 5000:5000 --env-file .env caido/grafana-auth-proxy`.

## Extending

Feel free to extend/fork the project for your own needs. The process is split in three main packages:
- `extraction`: Extract the token from the request
- `validation`: Validate the token
- `identity`: Find the user identity

Each package is designed with interfaces to allow new ways of providing the necessary information.
For example, it should be easy to extend the `identity` to fetch the user identity from a database.

A simple `go build` should then do the job to build a binary.
