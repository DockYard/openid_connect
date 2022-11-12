%HTTPoison.Response{
  status_code: 200,
  body: "{\"issuer\":\"http://localhost:8080/realms/master\",\"authorization_endpoint\":\"http://localhost:8080/realms/master/protocol/openid-connect/auth\",\"token_endpoint\":\"http://localhost:8080/realms/master/protocol/openid-connect/token\",\"introspection_endpoint\":\"http://localhost:8080/realms/master/protocol/openid-connect/token/introspect\",\"userinfo_endpoint\":\"http://localhost:8080/realms/master/protocol/openid-connect/userinfo\",\"end_session_endpoint\":\"http://localhost:8080/realms/master/protocol/openid-connect/logout\",\"frontchannel_logout_session_supported\":true,\"frontchannel_logout_supported\":true,\"jwks_uri\":\"http://localhost:8080/realms/master/protocol/openid-connect/certs\",\"check_session_iframe\":\"http://localhost:8080/realms/master/protocol/openid-connect/login-status-iframe.html\",\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\",\"urn:ietf:params:oauth:grant-type:device_code\",\"urn:openid:params:grant-type:ciba\"],\"acr_values_supported\":[\"0\",\"1\"],\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],\"subject_types_supported\":[\"public\",\"pairwise\"],\"id_token_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"id_token_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"id_token_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"userinfo_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\",\"none\"],\"userinfo_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"userinfo_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"request_object_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\",\"none\"],\"request_object_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"request_object_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\",\"query.jwt\",\"fragment.jwt\",\"form_post.jwt\",\"jwt\"],\"registration_endpoint\":\"http://localhost:8080/realms/master/clients-registrations/openid-connect\",\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"introspection_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"],\"introspection_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"authorization_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"authorization_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"authorization_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"claims_supported\":[\"aud\",\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\",\"acr\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":true,\"scopes_supported\":[\"openid\",\"phone\",\"acr\",\"microprofile-jwt\",\"email\",\"profile\",\"web-origins\",\"offline_access\",\"address\",\"roles\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"require_request_uri_registration\":true,\"code_challenge_methods_supported\":[\"plain\",\"S256\"],\"tls_client_certificate_bound_access_tokens\":true,\"revocation_endpoint\":\"http://localhost:8080/realms/master/protocol/openid-connect/revoke\",\"revocation_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_" <> ...,
  headers: [
    {"Referrer-Policy", "no-referrer"},
    {"X-Frame-Options", "SAMEORIGIN"},
    {"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
    {"Cache-Control", "no-cache, must-revalidate, no-transform, no-store"},
    {"X-Content-Type-Options", "nosniff"},
    {"X-XSS-Protection", "1; mode=block"},
    {"Content-Type", "application/json"},
    {"content-length", "5823"}
  ],
  request_url: "http://localhost:8080/realms/master/.well-known/openid-configuration",
  request: %HTTPoison.Request{
    method: :get,
    url: "http://localhost:8080/realms/master/.well-known/openid-configuration",
    headers: [],
    body: "",
    params: %{},
    options: []
  }
}
