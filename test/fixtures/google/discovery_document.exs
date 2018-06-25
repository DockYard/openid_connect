%HTTPoison.Response{
  body: %{
    "authorization_endpoint" => "https://accounts.google.com/o/oauth2/v2/auth",
    "claims_supported" => ["aud", "email", "email_verified", "exp", "family_name", "given_name", "iat", "iss", "locale", "name", "picture", "sub"],
    "code_challenge_methods_supported" => ["plain", "S256"],
    "id_token_signing_alg_values_supported" => ["RS256"],
    "issuer" => "https://accounts.google.com",
    "jwks_uri" => "https://www.googleapis.com/oauth2/v3/certs",
    "response_types_supported" => ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"],
    "revocation_endpoint" => "https://accounts.google.com/o/oauth2/revoke",
    "scopes_supported" => ["openid", "email", "profile"],
    "subject_types_supported" => ["public"],
    "token_endpoint" => "https://www.googleapis.com/oauth2/v4/token",
    "token_endpoint_auth_methods_supported" => ["client_secret_post", "client_secret_basic"],
    "userinfo_endpoint" => "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  headers: [
    {"Accept-Ranges", "none"},
    {"Vary", "Accept-Encoding"},
    {"Content-Type", "application/json"},
    {"Access-Control-Allow-Origin", "*"},
    {"Date", "Mon, 30 Apr 2018 06:25:58 GMT"},
    {"Expires", "Mon, 30 Apr 2018 07:25:58 GMT"},
    {"Last-Modified", "Mon, 01 Feb 2016 19:53:44 GMT"},
    {"X-Content-Type-Options", "nosniff"},
    {"Server", "sffe"},
    {"X-XSS-Protection", "1; mode=block"},
    {"Age", "700"},
    {"Cache-Control", "public, max-age=3600"},
    {"Alt-Svc",
     "hq=\":443\"; ma=2592000; quic=51303433; quic=51303432; quic=51303431; quic=51303339; quic=51303335,quic=\":443\"; ma=2592000; v=\"43,42,41,39,35\""},
    {"Transfer-Encoding", "chunked"}
  ],
  status_code: 200
}
