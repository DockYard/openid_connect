defmodule OpenIDConnect.DocumentTest do
  use ExUnit.Case, async: true
  import OpenIDConnect.Fixtures
  import OpenIDConnect.Document

  describe "fetch_document/1" do
    test "returns error when URL is nil" do
      assert fetch_document(nil) == {:error, :invalid_discovery_document_uri}
    end

    test "returns valid document from a given url" do
      {_bypass, uri} = start_fixture("auth0")

      assert {:ok, document} = fetch_document(uri)

      assert %OpenIDConnect.Document{
               authorization_endpoint: "https://common.auth0.com/authorize",
               claims_supported: [
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
               end_session_endpoint: nil,
               expires_at: expires_at,
               jwks: %JOSE.JWK{},
               raw: _json,
               response_types_supported: [
                 "code",
                 "token",
                 "id_token",
                 "code token",
                 "code id_token",
                 "id_token token",
                 "code id_token token"
               ],
               token_endpoint: "https://common.auth0.com/oauth/token"
             } = document

      assert DateTime.diff(expires_at, DateTime.utc_now()) in (60 * 60 - 10)..(60 * 60 + 10)
    end

    test "supports all gateway providers" do
      for provider <- ["auth0", "azure", "google", "keycloak", "okta", "onelogin", "vault"] do
        {_bypass, uri} = start_fixture(provider)
        assert {:ok, document} = fetch_document(uri)
        assert not is_nil(document.jwks)
      end
    end

    test "caches the document" do
      {_bypass, uri} = start_fixture("auth0")

      assert {:ok, document} = fetch_document(uri)
      assert {:ok, ^document} = fetch_document(uri)
    end

    test "handles non 2XX response codes" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/.well-known/discovery-document.json", fn conn ->
        Plug.Conn.resp(conn, 401, "{}")
      end)

      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"

      assert fetch_document(uri) == {:error, {401, "{}"}}
    end

    test "handles invalid responses" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/.well-known/discovery-document.json", fn conn ->
        Plug.Conn.resp(conn, 200, "{}")
      end)

      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"

      assert fetch_document(uri) == {:error, :invalid_document}
    end

    test "handles response errors" do
      bypass = Bypass.open()
      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"
      Bypass.down(bypass)

      assert fetch_document(uri) == {:error, %Mint.TransportError{reason: :econnrefused}}
    end

    test "takes expiration date from Cache-Control headers of the discovery document" do
      bypass = Bypass.open()
      endpoint = "http://localhost:#{bypass.port}/"
      provider = "vault"

      Bypass.expect_once(bypass, "GET", "/.well-known/jwks.json", fn conn ->
        {status_code, body, headers} = load_fixture(provider, "jwks")
        send_response(conn, status_code, body, headers)
      end)

      Bypass.expect_once(bypass, "GET", "/.well-known/discovery-document.json", fn conn ->
        {status_code, body, headers} = load_fixture(provider, "discovery_document")
        body = Map.merge(body, %{"jwks_uri" => "#{endpoint}.well-known/jwks.json"})

        headers =
          for {k, v} <- headers,
              k = String.downcase(k),
              k not in ["cache-control", "age"] do
            {k, v}
          end

        headers = headers ++ [{"cache-control", "max-age=300"}]
        send_response(conn, status_code, body, headers)
      end)

      uri = "#{endpoint}.well-known/discovery-document.json"

      assert {:ok, document} = fetch_document(uri)
      expected_expires_at = DateTime.add(DateTime.utc_now(), 300, :second)
      assert DateTime.diff(document.expires_at, expected_expires_at) in -3..3
    end

    test "takes expiration date from Cache-Control and Age headers of the discovery document" do
      bypass = Bypass.open()
      endpoint = "http://localhost:#{bypass.port}/"
      provider = "vault"

      Bypass.expect_once(bypass, "GET", "/.well-known/jwks.json", fn conn ->
        {status_code, body, headers} = load_fixture(provider, "jwks")
        send_response(conn, status_code, body, headers)
      end)

      Bypass.expect_once(bypass, "GET", "/.well-known/discovery-document.json", fn conn ->
        {status_code, body, headers} = load_fixture(provider, "discovery_document")
        body = Map.merge(body, %{"jwks_uri" => "#{endpoint}.well-known/jwks.json"})

        headers =
          for {k, v} <- headers,
              k = String.downcase(k),
              k not in ["cache-control", "age"] do
            {k, v}
          end

        headers = headers ++ [{"cache-control", "max-age=300"}, {"age", "100"}]
        send_response(conn, status_code, body, headers)
      end)

      uri = "#{endpoint}.well-known/discovery-document.json"

      assert {:ok, document} = fetch_document(uri)
      expected_expires_at = DateTime.add(DateTime.utc_now(), 300 - 100, :second)
      assert DateTime.diff(document.expires_at, expected_expires_at) in -3..3
    end

    test "takes expiration date from Cache-Control and Age headers of the jwks document" do
      bypass = Bypass.open()
      endpoint = "http://localhost:#{bypass.port}/"
      provider = "vault"

      Bypass.expect_once(bypass, "GET", "/.well-known/jwks.json", fn conn ->
        {status_code, body, headers} = load_fixture(provider, "jwks")

        headers =
          for {k, v} <- headers,
              k = String.downcase(k),
              k not in ["cache-control", "age"] do
            {k, v}
          end

        headers = headers ++ [{"cache-control", "max-age=300"}, {"age", "100"}]
        send_response(conn, status_code, body, headers)
      end)

      Bypass.expect_once(bypass, "GET", "/.well-known/discovery-document.json", fn conn ->
        {status_code, body, headers} = load_fixture(provider, "discovery_document")
        body = Map.merge(body, %{"jwks_uri" => "#{endpoint}.well-known/jwks.json"})

        send_response(conn, status_code, body, headers)
      end)

      uri = "#{endpoint}.well-known/discovery-document.json"

      assert {:ok, document} = fetch_document(uri)
      expected_expires_at = DateTime.add(DateTime.utc_now(), 300 - 100, :second)
      assert DateTime.diff(document.expires_at, expected_expires_at) in -3..3
    end
  end
end
