defmodule OpenIDConnectTest do
  use ExUnit.Case, async: true
  import OpenIDConnect.Fixtures
  import OpenIDConnect

  @config %{
    discovery_document_uri: nil,
    client_id: "CLIENT_ID",
    client_secret: "CLIENT_SECRET",
    redirect_uri: "https://localhost/redirect_uri",
    response_type: "code id_token token",
    scope: "openid email profile"
  }

  describe "authorization_uri/2" do
    test "generates authorization url with scope and response_type as binaries" do
      {_bypass, uri} = start_fixture("google")
      config = %{@config | discovery_document_uri: uri}

      assert authorization_uri(config) ==
               {:ok,
                "https://accounts.google.com/o/oauth2/v2/auth?" <>
                  "client_id=CLIENT_ID" <>
                  "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri" <>
                  "&response_type=code+id_token+token" <>
                  "&scope=openid+email+profile"}
    end

    test "generates authorization url with scope as enum" do
      {_bypass, uri} = start_fixture("google")
      config = %{@config | discovery_document_uri: uri, scope: ["openid", "email", "profile"]}

      assert authorization_uri(config) ==
               {:ok,
                "https://accounts.google.com/o/oauth2/v2/auth?" <>
                  "client_id=CLIENT_ID" <>
                  "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri" <>
                  "&response_type=code+id_token+token" <>
                  "&scope=openid+email+profile"}
    end

    test "generates authorization url with response_type as enum" do
      {_bypass, uri} = start_fixture("google")

      config = %{
        @config
        | discovery_document_uri: uri,
          response_type: ["code", "id_token", "token"]
      }

      assert authorization_uri(config) ==
               {:ok,
                "https://accounts.google.com/o/oauth2/v2/auth?" <>
                  "client_id=CLIENT_ID" <>
                  "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri" <>
                  "&response_type=code+id_token+token" <>
                  "&scope=openid+email+profile"}
    end

    test "returns error on empty scope" do
      {_bypass, uri} = start_fixture("google")

      config = %{@config | discovery_document_uri: uri, scope: nil}
      assert authorization_uri(config) == {:error, :invalid_scope}

      config = %{@config | discovery_document_uri: uri, scope: ""}
      assert authorization_uri(config) == {:error, :invalid_scope}

      config = %{@config | discovery_document_uri: uri, scope: []}
      assert authorization_uri(config) == {:error, :invalid_scope}
    end

    test "returns error on empty response_type" do
      {_bypass, uri} = start_fixture("google")

      config = %{@config | discovery_document_uri: uri, response_type: nil}
      assert authorization_uri(config) == {:error, :invalid_response_type}

      config = %{@config | discovery_document_uri: uri, response_type: ""}
      assert authorization_uri(config) == {:error, :invalid_response_type}

      config = %{@config | discovery_document_uri: uri, response_type: []}
      assert authorization_uri(config) == {:error, :invalid_response_type}
    end

    test "adds optional params" do
      {_bypass, uri} = start_fixture("google")
      config = %{@config | discovery_document_uri: uri}

      assert authorization_uri(config, %{"state" => "foo"}) ==
               {:ok,
                "https://accounts.google.com/o/oauth2/v2/auth?" <>
                  "client_id=CLIENT_ID" <>
                  "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri" <>
                  "&response_type=code+id_token+token" <>
                  "&scope=openid+email+profile" <>
                  "&state=foo"}
    end

    test "params can override default values" do
      {_bypass, uri} = start_fixture("google")
      config = %{@config | discovery_document_uri: uri}

      assert authorization_uri(config, %{client_id: "foo"}) ==
               {:ok,
                "https://accounts.google.com/o/oauth2/v2/auth?" <>
                  "client_id=foo" <>
                  "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri" <>
                  "&response_type=code+id_token+token" <>
                  "&scope=openid+email+profile"}
    end

    test "returns error when document is not available" do
      bypass = Bypass.open()
      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"
      Bypass.down(bypass)

      config = %{@config | discovery_document_uri: uri}

      assert authorization_uri(config, %{client_id: "foo"}) ==
               {:error, %Mint.TransportError{reason: :econnrefused}}
    end
  end

  describe "end_session_uri/2" do
    test "returns error when provider doesn't specify end_session_endpoint" do
      {_bypass, uri} = start_fixture("google")
      config = %{@config | discovery_document_uri: uri}

      assert end_session_uri(config) == {:error, :endpoint_not_set}
    end

    test "generates authorization url" do
      {_bypass, uri} = start_fixture("okta")
      config = %{@config | discovery_document_uri: uri}

      assert end_session_uri(config) ==
               {:ok, "https://common.okta.com/oauth2/v1/logout?client_id=CLIENT_ID"}
    end

    test "adds optional params" do
      {_bypass, uri} = start_fixture("okta")
      config = %{@config | discovery_document_uri: uri}

      assert end_session_uri(config, %{"state" => "foo"}) ==
               {:ok, "https://common.okta.com/oauth2/v1/logout?client_id=CLIENT_ID&state=foo"}
    end

    test "params can override default values" do
      {_bypass, uri} = start_fixture("okta")
      config = %{@config | discovery_document_uri: uri}

      assert end_session_uri(config, %{client_id: "foo"}) ==
               {:ok, "https://common.okta.com/oauth2/v1/logout?client_id=foo"}
    end

    test "returns error when document is not available" do
      bypass = Bypass.open()
      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"
      Bypass.down(bypass)

      config = %{@config | discovery_document_uri: uri}

      assert end_session_uri(config, %{client_id: "foo"}) ==
               {:error, %Mint.TransportError{reason: :econnrefused}}
    end
  end

  describe "fetch_tokens/2" do
    test "fetches the token from OAuth token endpoint" do
      bypass = Bypass.open()
      test_pid = self()

      token_response_attrs = %{
        "access_token" => "ACCESS_TOKEN",
        "id_token" => "ID_TOKEN",
        "refresh_token" => "REFRESH_TOKEN"
      }

      Bypass.expect_once(bypass, "POST", "/token", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(test_pid, {:req, body})
        Plug.Conn.resp(conn, 200, Jason.encode!(token_response_attrs))
      end)

      token_endpoint = "http://localhost:#{bypass.port}/token"
      {_bypass, uri} = start_fixture("google", %{token_endpoint: token_endpoint})
      config = %{@config | discovery_document_uri: uri}

      assert fetch_tokens(config, %{code: "1234", id_token: "abcd"}) ==
               {:ok, token_response_attrs}

      assert_receive {:req, body}

      assert body ==
               "client_id=CLIENT_ID" <>
                 "&client_secret=CLIENT_SECRET" <>
                 "&code=1234" <>
                 "&grant_type=authorization_code" <>
                 "&id_token=abcd" <>
                 "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri"
    end

    test "allows to override the default params" do
      bypass = Bypass.open()
      test_pid = self()

      token_response_attrs = %{
        "access_token" => "ACCESS_TOKEN",
        "id_token" => "ID_TOKEN",
        "refresh_token" => "REFRESH_TOKEN"
      }

      Bypass.expect_once(bypass, "POST", "/token", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(test_pid, {:req, body})
        Plug.Conn.resp(conn, 200, Jason.encode!(token_response_attrs))
      end)

      token_endpoint = "http://localhost:#{bypass.port}/token"
      {_bypass, uri} = start_fixture("google", %{token_endpoint: token_endpoint})
      config = %{@config | discovery_document_uri: uri}

      fetch_tokens(config, %{client_id: "foo"})

      assert_receive {:req, body}

      assert body ==
               "client_id=foo" <>
                 "&client_secret=CLIENT_SECRET" <>
                 "&grant_type=authorization_code" <>
                 "&redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri"
    end

    test "returns error when token endpoint is not available" do
      bypass = Bypass.open()
      Bypass.down(bypass)
      token_endpoint = "http://localhost:#{bypass.port}/token"
      {_bypass, uri} = start_fixture("google", %{token_endpoint: token_endpoint})
      config = %{@config | discovery_document_uri: uri}

      assert fetch_tokens(config, %{client_id: "foo"}) ==
               {:error, %Mint.TransportError{reason: :econnrefused}}
    end

    test "returns error when token endpoint is responds with non 2XX status code" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "POST", "/token", fn conn ->
        Plug.Conn.resp(conn, 401, Jason.encode!(%{"error" => "unauthorized"}))
      end)

      token_endpoint = "http://localhost:#{bypass.port}/token"
      {_bypass, uri} = start_fixture("google", %{token_endpoint: token_endpoint})
      config = %{@config | discovery_document_uri: uri}

      assert fetch_tokens(config, %{client_id: "foo"}) ==
               {:error, {401, "{\"error\":\"unauthorized\"}"}}
    end

    test "returns error when real provider token endpoint is responded with invalid code" do
      {_bypass, uri} = start_fixture("google")
      config = %{@config | discovery_document_uri: uri}
      assert {:error, {401, resp}} = fetch_tokens(config, %{code: "foo"})
      resp_json = Jason.decode!(resp)

      assert resp_json == %{
               "error" => "invalid_client",
               "error_description" => "The OAuth client was not found."
             }

      for provider <- ["auth0", "okta", "onelogin"] do
        {_bypass, uri} = start_fixture(provider)
        config = %{@config | discovery_document_uri: uri}
        assert {:error, {status, _resp}} = fetch_tokens(config, %{code: "foo"})
        assert status in 400..499
      end
    end

    test "returns error when document is not available" do
      bypass = Bypass.open()
      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"
      Bypass.down(bypass)

      config = %{@config | discovery_document_uri: uri}

      assert fetch_tokens(config, %{code: "foo"}) ==
               {:error, %Mint.TransportError{reason: :econnrefused}}
    end
  end

  describe "verify/2" do
    test "returns error when token has invalid format" do
      assert verify(@config, "foo") ==
               {:error, {:invalid_jwt, "invalid token format"}}
    end

    test "returns error when encoded token is not a JSON map" do
      token =
        ["fail", "fail", "fail"]
        |> Enum.map_join(".", fn header -> Base.encode64(header) end)

      assert verify(@config, token) ==
               {:error, {:invalid_jwt, "token claims did not contain a JSON payload"}}
    end

    test "returns error when encoded token is doesn't have valid 'alg'" do
      token =
        ["{}", "{}", "{}"]
        |> Enum.map_join(".", fn header -> Base.encode64(header) end)

      assert verify(@config, token) ==
               {:error, {:invalid_jwt, "no `alg` found in token"}}
    end

    test "returns error when token is valid but invalid for a provider" do
      {_bypass, uri} = start_fixture("okta")
      config = %{@config | discovery_document_uri: uri}
      {jwk, []} = Code.eval_file("test/fixtures/jwks/jwk.exs")

      claims = %{"email" => "brian@example.com"}

      {_alg, token} =
        jwk
        |> JOSE.JWK.from()
        |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
        |> JOSE.JWS.compact()

      assert verify(config, token) == {:error, {:invalid_jwt, "verification failed"}}
    end

    test "returns claims when encoded token is valid" do
      {jwks, []} = Code.eval_file("test/fixtures/jwks/jwk.exs")
      jwk = JOSE.JWK.from(jwks)
      {_, jwk_pubkey} = JOSE.JWK.to_public_map(jwk)

      {_bypass, uri} = start_fixture("vault", %{"jwks" => jwk_pubkey})
      config = %{@config | discovery_document_uri: uri}

      claims = %{"email" => "brian@example.com"}

      {_alg, token} =
        jwk
        |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
        |> JOSE.JWS.compact()

      assert verify(config, token) == {:ok, claims}
    end

    test "returns claims when encoded token is valid using multiple keys" do
      {jwks, []} = Code.eval_file("test/fixtures/jwks/jwks.exs")

      jwk =
        jwks
        |> Map.fetch!("keys")
        |> List.first()
        |> JOSE.JWK.from()

      {_, jwk_pubkey} = JOSE.JWK.to_public_map(jwk)

      {_bypass, uri} = start_fixture("vault", %{"jwks" => jwk_pubkey})
      config = %{@config | discovery_document_uri: uri}

      claims = %{"email" => "brian@example.com"}

      {_alg, token} =
        jwk
        |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
        |> JOSE.JWS.compact()

      assert verify(config, token) == {:ok, claims}
    end

    test "returns error when token is altered" do
      {jwks, []} = Code.eval_file("test/fixtures/jwks/jwk.exs")
      jwk = JOSE.JWK.from(jwks)
      {_, jwk_pubkey} = JOSE.JWK.to_public_map(jwk)

      {_bypass, uri} = start_fixture("vault", %{"jwks" => jwk_pubkey})
      config = %{@config | discovery_document_uri: uri}

      claims = %{"email" => "brian@example.com"}

      {_alg, token} =
        jwk
        |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
        |> JOSE.JWS.compact()

      assert verify(config, token <> ":)") == {:error, {:invalid_jwt, "verification failed"}}
    end

    test "returns error when document is not available" do
      {jwks, []} = Code.eval_file("test/fixtures/jwks/jwk.exs")

      bypass = Bypass.open()
      uri = "http://localhost:#{bypass.port}/.well-known/discovery-document.json"
      Bypass.down(bypass)

      config = %{@config | discovery_document_uri: uri}

      claims = %{"email" => "brian@example.com"}

      {_alg, token} =
        jwks
        |> JOSE.JWK.from()
        |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
        |> JOSE.JWS.compact()

      assert verify(config, token) ==
               {:error, %Mint.TransportError{reason: :econnrefused}}
    end
  end
end
