%HTTPoison.Response{
  status_code: 200,
  body: "{\"issuer\":\"http://0.0.0.0:8200/v1/identity/oidc/provider/default\",\"jwks_uri\":\"http://0.0.0.0:8200/v1/identity/oidc/provider/default/.well-known/keys\",\"authorization_endpoint\":\"http://0.0.0.0:8200/ui/vault/identity/oidc/provider/default/authorize\",\"token_endpoint\":\"http://0.0.0.0:8200/v1/identity/oidc/provider/default/token\",\"userinfo_endpoint\":\"http://0.0.0.0:8200/v1/identity/oidc/provider/default/userinfo\",\"request_parameter_supported\":false,\"request_uri_parameter_supported\":false,\"id_token_signing_alg_values_supported\":[\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"EdDSA\"],\"response_types_supported\":[\"code\"],\"scopes_supported\":[\"openid\"],\"claims_supported\":[],\"subject_types_supported\":[\"public\"],\"grant_types_supported\":[\"authorization_code\"],\"token_endpoint_auth_methods_supported\":[\"none\",\"client_secret_basic\",\"client_secret_post\"]}",
  headers: [
    {"Cache-Control", "max-age=3600"},
    {"Content-Type", "application/json"},
    {"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
    {"Date", "Sat, 12 Nov 2022 19:50:54 GMT"},
    {"Content-Length", "849"}
  ],
  request_url: "http://127.0.0.1:8200/v1/identity/oidc/provider/default/.well-known/openid-configuration",
  request: %HTTPoison.Request{
    method: :get,
    url: "http://127.0.0.1:8200/v1/identity/oidc/provider/default/.well-known/openid-configuration",
    headers: [],
    body: "",
    params: %{},
    options: []
  }
}
