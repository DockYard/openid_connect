%HTTPoison.Response{
  status_code: 200,
  body: "{\"issuer\":\"https://common.okta.com\",\"authorization_endpoint\":\"https://common.okta.com/oauth2/v1/authorize\",\"token_endpoint\":\"https://common.okta.com/oauth2/v1/token\",\"userinfo_endpoint\":\"https://common.okta.com/oauth2/v1/userinfo\",\"registration_endpoint\":\"https://common.okta.com/oauth2/v1/clients\",\"jwks_uri\":\"https://common.okta.com/oauth2/v1/keys\",\"response_types_supported\":[\"code\",\"id_token\",\"code id_token\",\"code token\",\"id_token token\",\"code id_token token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\",\"okta_post_message\"],\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"urn:ietf:params:oauth:grant-type:device_code\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"scopes_supported\":[\"openid\",\"email\",\"profile\",\"address\",\"phone\",\"offline_access\",\"groups\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"none\"],\"claims_supported\":[\"iss\",\"ver\",\"sub\",\"aud\",\"iat\",\"exp\",\"jti\",\"auth_time\",\"amr\",\"idp\",\"nonce\",\"name\",\"nickname\",\"preferred_username\",\"given_name\",\"middle_name\",\"family_name\",\"email\",\"email_verified\",\"profile\",\"zoneinfo\",\"locale\",\"address\",\"phone_number\",\"picture\",\"website\",\"gender\",\"birthdate\",\"updated_at\",\"at_hash\",\"c_hash\"],\"code_challenge_methods_supported\":[\"S256\"],\"introspection_endpoint\":\"https://common.okta.com/oauth2/v1/introspect\",\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"none\"],\"revocation_endpoint\":\"https://common.okta.com/oauth2/v1/revoke\",\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\",\"none\"],\"end_session_endpoint\":\"https://common.okta.com/oauth2/v1/logout\",\"request_parameter_supported\":true,\"request_object_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\"],\"device_authorization_endpoint\":\"https://common.okta.com/oauth2/v1/device/authorize\"}",
  headers: [
    {"Date", "Sat, 12 Nov 2022 19:40:24 GMT"},
    {"Content-Type", "application/json"},
    {"Transfer-Encoding", "chunked"},
    {"Connection", "keep-alive"},
    {"Server", "nginx"},
    {"Public-Key-Pins-Report-Only",
     "pin-sha256=\"r5EfzZxQVvQpKo3AgYRaT7X2bDO/kj3ACwmxfdT2zt8=\"; pin-sha256=\"MaqlcUgk2mvY/RFSGeSwBRkI+rZ6/dxe/DuQfBT/vnQ=\"; pin-sha256=\"72G5IEvDEWn+EThf3qjR7/bQSWaS2ZSLqolhnO6iyJI=\"; pin-sha256=\"rrV6CLCCvqnk89gWibYT0JO6fNQ8cCit7GGoiVTjCOg=\"; max-age=60; report-uri=\"https://okta.report-uri.com/r/default/hpkp/reportOnly\""},
    {"x-xss-protection", "0"},
    {"p3p", "CP=\"HONK\""},
    {"content-security-policy",
     "default-src 'self' common.okta.com *.oktacdn.com; connect-src 'self' common.okta.com common-admin.okta.com *.oktacdn.com *.mixpanel.com *.mapbox.com app.pendo.io data.pendo.io pendo-static-5634101834153984.storage.googleapis.com pendo-static-5391521872216064.storage.googleapis.com common.kerberos.okta.com https://oinmanager.okta.com data:; script-src 'unsafe-inline' 'unsafe-eval' 'self' common.okta.com *.oktacdn.com; style-src 'unsafe-inline' 'self' common.okta.com *.oktacdn.com app.pendo.io cdn.pendo.io pendo-static-5634101834153984.storage.googleapis.com pendo-static-5391521872216064.storage.googleapis.com; frame-src 'self' common.okta.com common-admin.okta.com login.okta.com; img-src 'self' common.okta.com *.oktacdn.com *.tiles.mapbox.com *.mapbox.com app.pendo.io data.pendo.io cdn.pendo.io pendo-static-5634101834153984.storage.googleapis.com pendo-static-5391521872216064.storage.googleapis.com data: blob:; font-src 'self' common.okta.com data: *.oktacdn.com fonts.gstatic.com; frame-ancestors 'self'"},
    {"expect-ct",
     "report-uri=\"https://oktaexpectct.report-uri.com/r/t/ct/reportOnly\", max-age=0"},
    {"cache-control", "max-age=86400, must-revalidate"},
    {"expires", "Sun, 13 Nov 2022 19:40:24 GMT"},
    {"vary", "Origin"},
    {"x-content-type-options", "nosniff"},
    {"Strict-Transport-Security", "max-age=315360000; includeSubDomains"},
    {"X-Okta-Request-Id", "Y2_2qFFQ3zhcoZh3312xKwAAARU"}
  ],
  request_url: "https://common.okta.com/.well-known/openid-configuration",
  request: %HTTPoison.Request{
    method: :get,
    url: "https://common.okta.com/.well-known/openid-configuration",
    headers: [],
    body: "",
    params: %{},
    options: []
  }
}
