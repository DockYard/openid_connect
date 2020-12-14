use Mix.Config

config :openid_connect, :http_client, OpenIDConnect.HTTPClientMock

config :openid_connect, :providers,
  google: [
    discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
    client_id: "CLIENT_ID_1",
    client_secret: "CLIENT_SECRET_1",
    redirect_uri: "https://dev.example.com:4200/session",
    scope: "openid email profile",
    response_type: "code id_token token"
  ],
  google_auth_basic: [
    discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
    client_id: "CLIENT_ID_1",
    client_secret: "CLIENT_SECRET_1",
    redirect_uri: "https://dev.example.com:4200/session",
    scope: "openid email profile",
    response_type: "code id_token token",
    token_endpoint_auth_method: "client_secret_basic"
  ]
