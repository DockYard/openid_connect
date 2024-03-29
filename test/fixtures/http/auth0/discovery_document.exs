%{
  status_code: 200,
  body: %{
    "authorization_endpoint" => "https://common.auth0.com/authorize",
    "claims_supported" => [
      "aud",
      "auth_time",
      "created_at",
      "email",
      "email_verified",
      "exp",
      "family_name",
      "given_name",
      "iat",
      "identities",
      "iss",
      "name",
      "nickname",
      "phone_number",
      "picture",
      "sub"
    ],
    "code_challenge_methods_supported" => ["S256", "plain"],
    "device_authorization_endpoint" => "https://common.auth0.com/oauth/device/code",
    "id_token_signing_alg_values_supported" => ["HS256", "RS256"],
    "issuer" => "https://common.auth0.com/",
    "jwks_uri" => "https://common.auth0.com/.well-known/jwks.json",
    "mfa_challenge_endpoint" => "https://common.auth0.com/mfa/challenge",
    "registration_endpoint" => "https://common.auth0.com/oidc/register",
    "request_parameter_supported" => false,
    "request_uri_parameter_supported" => false,
    "response_modes_supported" => ["query", "fragment", "form_post"],
    "response_types_supported" => [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token"
    ],
    "revocation_endpoint" => "https://common.auth0.com/oauth/revoke",
    "scopes_supported" => [
      "openid",
      "profile",
      "offline_access",
      "name",
      "given_name",
      "family_name",
      "nickname",
      "email",
      "email_verified",
      "picture",
      "created_at",
      "identities",
      "phone",
      "address"
    ],
    "subject_types_supported" => ["public"],
    "token_endpoint" => "https://common.auth0.com/oauth/token",
    "token_endpoint_auth_methods_supported" => ["client_secret_basic", "client_secret_post"],
    "userinfo_endpoint" => "https://common.auth0.com/userinfo"
  },
  headers: [
    {"Date", "Sat, 12 Nov 2022 19:57:59 GMT"},
    {"Content-Type", "application/json; charset=utf-8"},
    {"CF-Ray", "7691d6fb8d50f96b-SJC"},
    {"Access-Control-Allow-Origin", "*"},
    {"Cache-Control", "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"},
    {"Last-Modified", "Sat, 12 Nov 2022 19:57:59 GMT"},
    {"Strict-Transport-Security", "max-age=31536000"},
    {"Vary", "Accept-Encoding, Origin, Accept-Encoding"},
    {"CF-Cache-Status", "MISS"},
    {"Access-Control-Allow-Credentials", "false"},
    {"Access-Control-Expose-Headers",
     "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset"},
    {"ot-baggage-auth0-request-id", "7691d6fb8d50f96b"},
    {"ot-tracer-sampled", "true"},
    {"ot-tracer-spanid", "273c5b5354590f5b"},
    {"ot-tracer-traceid", "5026231a2155221a"},
    {"traceparent", "00-00000000000000005026231a2155221a-273c5b5354590f5b-01"},
    {"tracestate", "auth0-request-id=7691d6fb8d50f96b,auth0=true"},
    {"X-Auth0-RequestId", "04426ddefbd03b8009aa"},
    {"X-Content-Type-Options", "nosniff"},
    {"X-RateLimit-Limit", "300"},
    {"X-RateLimit-Remaining", "299"},
    {"X-RateLimit-Reset", "1668283080"},
    {"Server", "cloudflare"},
    {"alt-svc", "h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400"}
  ]
}
