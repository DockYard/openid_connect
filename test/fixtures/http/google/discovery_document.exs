%HTTPoison.Response{
  status_code: 200,
  body: "{\n \"issuer\": \"https://accounts.google.com\",\n \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\",\n \"device_authorization_endpoint\": \"https://oauth2.googleapis.com/device/code\",\n \"token_endpoint\": \"https://oauth2.googleapis.com/token\",\n \"userinfo_endpoint\": \"https://openidconnect.googleapis.com/v1/userinfo\",\n \"revocation_endpoint\": \"https://oauth2.googleapis.com/revoke\",\n \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\",\n \"response_types_supported\": [\n  \"code\",\n  \"token\",\n  \"id_token\",\n  \"code token\",\n  \"code id_token\",\n  \"token id_token\",\n  \"code token id_token\",\n  \"none\"\n ],\n \"subject_types_supported\": [\n  \"public\"\n ],\n \"id_token_signing_alg_values_supported\": [\n  \"RS256\"\n ],\n \"scopes_supported\": [\n  \"openid\",\n  \"email\",\n  \"profile\"\n ],\n \"token_endpoint_auth_methods_supported\": [\n  \"client_secret_post\",\n  \"client_secret_basic\"\n ],\n \"claims_supported\": [\n  \"aud\",\n  \"email\",\n  \"email_verified\",\n  \"exp\",\n  \"family_name\",\n  \"given_name\",\n  \"iat\",\n  \"iss\",\n  \"locale\",\n  \"name\",\n  \"picture\",\n  \"sub\"\n ],\n \"code_challenge_methods_supported\": [\n  \"plain\",\n  \"S256\"\n ],\n \"grant_types_supported\": [\n  \"authorization_code\",\n  \"refresh_token\",\n  \"urn:ietf:params:oauth:grant-type:device_code\",\n  \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n ]\n}\n",
  headers: [
    {"Accept-Ranges", "bytes"},
    {"Vary", "Accept-Encoding"},
    {"Access-Control-Allow-Origin", "*"},
    {"Content-Security-Policy-Report-Only",
     "require-trusted-types-for 'script'; report-uri https://csp.withgoogle.com/csp/federated-signon-mpm-access"},
    {"Cross-Origin-Opener-Policy",
     "same-origin; report-to=\"federated-signon-mpm-access\""},
    {"Report-To",
     "{\"group\":\"federated-signon-mpm-access\",\"max_age\":2592000,\"endpoints\":[{\"url\":\"https://csp.withgoogle.com/csp/report-to/federated-signon-mpm-access\"}]}"},
    {"Content-Length", "1280"},
    {"X-Content-Type-Options", "nosniff"},
    {"Server", "sffe"},
    {"X-XSS-Protection", "0"},
    {"Date", "Sat, 12 Nov 2022 19:03:58 GMT"},
    {"Expires", "Sat, 12 Nov 2022 20:03:58 GMT"},
    {"Cache-Control", "public, max-age=3600"},
    {"Age", "1698"},
    {"Last-Modified", "Thu, 16 Jan 2020 21:53:16 GMT"},
    {"Content-Type", "application/json"},
    {"Alt-Svc",
     "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\""}
  ],
  request_url: "https://accounts.google.com/.well-known/openid-configuration",
  request: %HTTPoison.Request{
    method: :get,
    url: "https://accounts.google.com/.well-known/openid-configuration",
    headers: [],
    body: "",
    params: %{},
    options: []
  }
}
