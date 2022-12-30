defmodule OpenIDConnectTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!
  setup :set_jose_json_lib

  @google_document Fixtures.load("google", :discovery_document)
  @google_certs Fixtures.load("google", :jwks)

  alias OpenIDConnect.{HTTPClientMock, MockWorker}

  # XXX: Unskip this test when we're back on Hex
  @tag :skip
  test "README install version check" do
    app = :openid_connect

    app_version = "#{Application.spec(app, :vsn)}"
    readme = File.read!("README.md")
    [_, readme_versions] = Regex.run(~r/{:#{app}, "(.+)"}/, readme)

    assert Version.match?(
             app_version,
             readme_versions
           ),
           """
           Install version constraint in README.md does not match to current app version.
           Current App Version: #{app_version}
           Readme Install Versions: #{readme_versions}
           """
  end

  describe "update_documents" do
    test "when the new documents are retrieved successfully" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      HTTPClientMock
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration",
                         _headers,
                         _opts ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, _opts ->
        @google_certs
      end)

      expected_document =
        @google_document
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()
        |> OpenIDConnect.normalize_discovery_document()

      expected_jwk =
        @google_certs
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()
        |> JOSE.JWK.from()

      {:ok,
       %{
         discovery_document: discovery_document,
         jwk: jwk,
         remaining_lifetime: remaining_lifetime
       }} = OpenIDConnect.update_documents(config)

      assert expected_document == discovery_document
      assert expected_jwk == jwk
      assert remaining_lifetime == 21_527
    end

    test "fails during open id configuration document with HTTPoison error" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      expect(
        HTTPClientMock,
        :get,
        fn "https://accounts.google.com/.well-known/openid-configuration", _headers, _opts ->
          {:ok, %HTTPoison.Error{id: nil, reason: :nxdomain}}
        end
      )

      assert OpenIDConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Error{id: nil, reason: :nxdomain}}
    end

    test "non-200 response for open id configuration document" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      expect(
        HTTPClientMock,
        :get,
        fn "https://accounts.google.com/.well-known/openid-configuration", _headers, _opts ->
          {:ok, %HTTPoison.Response{status_code: 404}}
        end
      )

      assert OpenIDConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Response{status_code: 404}}
    end

    test "fails during certs with HTTPoison error" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      HTTPClientMock
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration",
                         _headers,
                         _opts ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, _opts ->
        {:ok, %HTTPoison.Error{reason: :nxdomain}}
      end)

      assert OpenIDConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Error{id: nil, reason: :nxdomain}}
    end

    test "non-200 response for certs" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      HTTPClientMock
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration",
                         _headers,
                         _opts ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, _opts ->
        {:ok, %HTTPoison.Response{status_code: 404}}
      end)

      assert OpenIDConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Response{status_code: 404}}
    end

    test "with HTTP client options" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      opts = [ssl: [{:verify, :verify_none}]]
      Application.put_env(:openid_connect, :http_client_options, opts)

      HTTPClientMock
      |> expect(:get, fn
        "https://accounts.google.com/.well-known/openid-configuration", _headers, ^opts ->
          @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, ^opts ->
        {:ok, %HTTPoison.Response{status_code: 404}}
      end)

      assert OpenIDConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Response{status_code: 404}}
    end
  end

  describe "normalize_discovery_document" do
    test "defaults to empty list if claims_supported is missing" do
      document_without_claims =
        @google_document
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()
        |> Map.delete("claims_supported")

      normalized_claims =
        document_without_claims
        |> OpenIDConnect.normalize_discovery_document()
        |> Map.get("claims_supported")

      assert normalized_claims == []
    end
  end

  describe "generating the authorization uri" do
    test "with default worker name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code+id_token+token&scope=openid+email+profile"

        assert OpenIDConnect.authorization_uri("google") == expected
      after
        GenServer.stop(pid)
      end
    end

    test "with optional params" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code+id_token+token&scope=openid+email+profile&hd=dockyard.com"

        assert OpenIDConnect.authorization_uri("google", %{"hd" => "dockyard.com"}) == expected
      after
        GenServer.stop(pid)
      end
    end

    test "with overridden params" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code+id_token+token&scope=something+else"

        assert OpenIDConnect.authorization_uri("google", %{scope: "something else"}) == expected
      after
        GenServer.stop(pid)
      end
    end

    test "with custom worker name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :other_openid_worker)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code+id_token+token&scope=openid+email+profile"

        assert OpenIDConnect.authorization_uri("google", %{}, :other_openid_worker) == expected
      after
        GenServer.stop(pid)
      end
    end
  end

  describe "fetching tokens" do
    test "when token fetch is successful" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      config = GenServer.call(:openid_connect, {:config, "google"})

      form_body = [
        client_id: config[:client_id],
        client_secret: config[:client_secret],
        code: "1234",
        grant_type: "authorization_code",
        redirect_uri: config[:redirect_uri]
      ]

      try do
        expect(HTTPClientMock, :post, fn "https://oauth2.googleapis.com/token",
                                         {:form, ^form_body},
                                         _headers,
                                         _opts ->
          {:ok, %HTTPoison.Response{status_code: 200, body: Jason.encode!(%{})}}
        end)

        {:ok, body} = OpenIDConnect.fetch_tokens("google", %{code: "1234"})

        assert body == %{}
      after
        GenServer.stop(pid)
      end
    end

    test "when token fetch is successful with a different GenServer name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :other_openid_connect)

      config = GenServer.call(:other_openid_connect, {:config, "google"})

      form_body = [
        client_id: config[:client_id],
        client_secret: config[:client_secret],
        code: "1234",
        grant_type: "authorization_code",
        id_token: "abcd",
        redirect_uri: config[:redirect_uri]
      ]

      try do
        expect(HTTPClientMock, :post, fn "https://oauth2.googleapis.com/token",
                                         {:form, ^form_body},
                                         _headers,
                                         _opts ->
          {:ok, %HTTPoison.Response{status_code: 200, body: Jason.encode!(%{})}}
        end)

        {:ok, body} =
          OpenIDConnect.fetch_tokens(
            "google",
            %{code: "1234", id_token: "abcd"},
            :other_openid_connect
          )

        assert body == %{}
      after
        GenServer.stop(pid)
      end
    end

    test "when params are overridden" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      config = GenServer.call(:openid_connect, {:config, "google"})

      form_body = [
        client_id: config[:client_id],
        client_secret: config[:client_secret],
        grant_type: "refresh_token",
        redirect_uri: config[:redirect_uri]
      ]

      try do
        expect(HTTPClientMock, :post, fn "https://oauth2.googleapis.com/token",
                                         {:form, ^form_body},
                                         _headers,
                                         _opts ->
          {:ok, %HTTPoison.Response{status_code: 200, body: Jason.encode!(%{})}}
        end)

        {:ok, body} = OpenIDConnect.fetch_tokens("google", %{grant_type: "refresh_token"})

        assert body == %{}
      after
        GenServer.stop(pid)
      end
    end

    test "when token fetch fails with bad domain" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      http_error = %HTTPoison.Error{reason: :nxdomain}

      try do
        expect(HTTPClientMock, :post, fn "https://oauth2.googleapis.com/token",
                                         {:form, _form_body},
                                         _headers,
                                         _opts ->
          {:ok, http_error}
        end)

        resp = OpenIDConnect.fetch_tokens("google", %{code: "1234"})

        assert resp == {:error, :fetch_tokens, http_error}
      after
        GenServer.stop(pid)
      end
    end

    test "when token fetch doesn't return a 200 response" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      http_error = %HTTPoison.Response{status_code: 404}

      try do
        expect(HTTPClientMock, :post, fn "https://oauth2.googleapis.com/token",
                                         {:form, _form_body},
                                         _headers,
                                         _opts ->
          {:ok, http_error}
        end)

        resp = OpenIDConnect.fetch_tokens("google", %{code: "1234"})

        assert resp == {:error, :fetch_tokens, http_error}
      after
        GenServer.stop(pid)
      end
    end
  end

  describe "jwt verification" do
    test "is successful" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/jwks/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify("google", token)
        assert result == {:ok, claims}
      after
        GenServer.stop(pid)
      end
    end

    test "is successful with multiple jwks" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/jwks/jwks.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk
          |> Map.get("keys")
          |> List.last()
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify("google", token)
        assert result == {:ok, claims}
      after
        GenServer.stop(pid)
      end
    end

    test "fails with invalid token format" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/jwks/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        result = OpenIDConnect.verify("google", "fail")
        assert result == {:error, :verify, "invalid token format"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails with invalid token claims format" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/jwks/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        token =
          [
            "fail",
            "fail",
            "fail"
          ]
          |> Enum.map_join(".", fn header -> Base.encode64(header) end)

        result = OpenIDConnect.verify("google", token)
        assert result == {:error, :verify, "token claims did not contain a JSON payload"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails with token not including algorithm hint" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/jwks/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        token =
          [
            "{}",
            "{}",
            "{}"
          ]
          |> Enum.map_join(".", fn header -> Base.encode64(header) end)

        result = OpenIDConnect.verify("google", token)
        assert result == {:error, :verify, "no `alg` found in token"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails when verification fails" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk1, []} = Code.eval_file("test/fixtures/jwks/jwk1.exs")
        {jwk2, []} = Code.eval_file("test/fixtures/jwks/jwk2.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk1)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk2
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify("google", token)
        assert result == {:error, :verify, "verification failed"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails when verification fails due to token manipulation" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/jwks/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify("google", token <> " :)")
        assert result == {:error, :verify, "verification error"}
      after
        GenServer.stop(pid)
      end
    end
  end

  defp set_jose_json_lib(_) do
    JOSE.json_module(JasonEncoder)
    []
  end
end
