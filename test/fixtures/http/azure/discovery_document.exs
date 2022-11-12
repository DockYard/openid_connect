%HTTPoison.Response{
  status_code: 200,
  body: "{\"token_endpoint\":\"https://login.microsoftonline.com/common/oauth2/v2.0/token\",\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"private_key_jwt\",\"client_secret_basic\"],\"jwks_uri\":\"https://login.microsoftonline.com/common/discovery/v2.0/keys\",\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"subject_types_supported\":[\"pairwise\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"response_types_supported\":[\"code\",\"id_token\",\"code id_token\",\"id_token token\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"offline_access\"],\"issuer\":\"https://login.microsoftonline.com/{tenantid}/v2.0\",\"request_uri_parameter_supported\":false,\"userinfo_endpoint\":\"https://graph.microsoft.com/oidc/userinfo\",\"authorization_endpoint\":\"https://login.microsoftonline.com/common/oauth2/v2.0/authorize\",\"device_authorization_endpoint\":\"https://login.microsoftonline.com/common/oauth2/v2.0/devicecode\",\"http_logout_supported\":true,\"frontchannel_logout_supported\":true,\"end_session_endpoint\":\"https://login.microsoftonline.com/common/oauth2/v2.0/logout\",\"claims_supported\":[\"sub\",\"iss\",\"cloud_instance_name\",\"cloud_instance_host_name\",\"cloud_graph_host_name\",\"msgraph_host\",\"aud\",\"exp\",\"iat\",\"auth_time\",\"acr\",\"nonce\",\"preferred_username\",\"name\",\"tid\",\"ver\",\"at_hash\",\"c_hash\",\"email\"],\"kerberos_endpoint\":\"https://login.microsoftonline.com/common/kerberos\",\"tenant_region_scope\":null,\"cloud_instance_name\":\"microsoftonline.com\",\"cloud_graph_host_name\":\"graph.windows.net\",\"msgraph_host\":\"graph.microsoft.com\",\"rbac_url\":\"https://pas.windows.net\"}",
  headers: [
    {"Cache-Control", "max-age=86400, private"},
    {"Content-Type", "application/json; charset=utf-8"},
    {"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
    {"X-Content-Type-Options", "nosniff"},
    {"Access-Control-Allow-Origin", "*"},
    {"Access-Control-Allow-Methods", "GET, OPTIONS"},
    {"P3P", "CP=\"DSP CUR OTPi IND OTRi ONL FIN\""},
    {"x-ms-request-id", "d81e7f56-0451-4de4-a5c5-4af112d02001"},
    {"x-ms-ests-server", "2.1.14006.10 - NCUS ProdSlices"},
    {"X-XSS-Protection", "0"},
    {"Set-Cookie",
     "fpc=AuKLSwY1b3xLiInKP16p3E4; expires=Mon, 12-Dec-2022 19:36:30 GMT; path=/; secure; HttpOnly; SameSite=None"},
    {"Set-Cookie",
     "esctx=AQABAAAAAAD--DLA3VO7QrddgJg7Wevr2ALKzZMjPY-Tt7ffB-f_7y4AMTUR-4m-AQDAi0jJ1K4_N7dY0CZmKZdSweQPMgerZ-TeKnty43nfmYRZS2G39bKUZp5erQLwiB9rkuLis4_ee_cAZK7nh1pkqOh0_t52P9svf75Le0-ex8iyPVhexTbIROTaaYvo6Fl9DFqOtZOnmQplc6ken-ddUcLbnZRSKOTFdr03VB8oSt5gD2BBw2e5qeBuocgX0hS-W-FNbG0gAA; domain=.login.microsoftonline.com; path=/; secure; HttpOnly; SameSite=None"},
    {"Set-Cookie",
     "x-ms-gateway-slice=estsfd; path=/; secure; samesite=none; httponly"},
    {"Set-Cookie",
     "stsservicecookie=estsfd; path=/; secure; samesite=none; httponly"},
    {"Date", "Sat, 12 Nov 2022 19:36:29 GMT"},
    {"Content-Length", "1547"}
  ],
  request_url: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
  request: %HTTPoison.Request{
    method: :get,
    url: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    headers: [],
    body: "",
    params: %{},
    options: []
  }
}
