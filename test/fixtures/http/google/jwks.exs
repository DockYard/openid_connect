%HTTPoison.Response{
  status_code: 200,
  body: "{\n  \"keys\": [\n    {\n      \"use\": \"sig\",\n      \"kid\": \"f451345fad08101bfb345cf642a2da9267b9ebeb\",\n      \"kty\": \"RSA\",\n      \"alg\": \"RS256\",\n      \"n\": \"ppFPAZUqIVqCf_SffT6xDCXu1R7aRoT6TNT5_Q8PKxkkqbOVysJPNwliF-486VeM8KNW8onFOv0GkP0lJ2ASrVgyMG1qmlGUlKug64dMQXPxSlVUCXCPN676W5IZTvT0tD2byM_29HZXnOifRg-d7PRRvIBLSUWe-fGb1-tP2w65SOW-W6LuOjGzLNPJFYQvHyUx_uXHOCfIoSb8kaMwx8bCWvKc76yT0DG1wcygGXKuFQHW-Sdi1j_6bF19lVu30DX-jhYsNMUnGUr6g2iycQ50pWMORZqvcHVOH1bbDrWuz0b564sK0ET2B3XDR37djNQ305PxiQZaBStm-hM8Aw\",\n      \"e\": \"AQAB\"\n    },\n    {\n      \"n\": \"z8PS6saDU3h5ZbQb3Lwl_Arwgu65ECMi79KUlzx4tqk8bgxtaaHcqyvWqVdsA9H6Q2ZtQhBZivqV4Jg0HoPHcEwv46SEziFQNR2LH86e-WIDI5pk2NKg_9cFMee9Mz7f_NSQJ3uyD1pu86bdUTYhCw57DbEVDOuubClNMUV456dWx7dx5W4kdcQe63vGg9LXQ-9PPz9AL-0ZKr8eQEHp4KRfRUfngjqjYBMTFuuo38l94KR99B04Z-FboGnqYLgNxctwZ9eXbCerb9bV5-Q9Gb3zoo0x1h90tFdgmC2ZU1xcIIjHmFqJ29mSDZHYAAYtMNAeWreK4gqWJunc9o0vpQ\",\n      \"kty\": \"RSA\",\n      \"alg\": \"RS256\",\n      \"kid\": \"713fd68c966e29380981edc0164a2f6c06c5702a\",\n      \"use\": \"sig\",\n      \"e\": \"AQAB\"\n    }\n  ]\n}\n",
  headers: [
    {"Server", "scaffolding on HTTPServer2"},
    {"X-XSS-Protection", "0"},
    {"X-Frame-Options", "SAMEORIGIN"},
    {"X-Content-Type-Options", "nosniff"},
    {"Date", "Sat, 12 Nov 2022 19:33:44 GMT"},
    {"Expires", "Sun, 13 Nov 2022 01:32:36 GMT"},
    {"Cache-Control", "public, max-age=21532, must-revalidate, no-transform"},
    {"Content-Type", "application/json; charset=UTF-8"},
    {"Age", "5"},
    {"Alt-Svc",
     "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\""},
    {"Accept-Ranges", "none"},
    {"Vary", "Origin,X-Origin,Referer,Accept-Encoding"},
    {"Transfer-Encoding", "chunked"}
  ],
  request_url: "https://www.googleapis.com/oauth2/v3/certs",
  request: %HTTPoison.Request{
    method: :get,
    url: "https://www.googleapis.com/oauth2/v3/certs",
    headers: [],
    body: "",
    params: %{},
    options: []
  }
}
