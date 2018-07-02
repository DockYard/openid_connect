defmodule OpenIDConnectTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!
  setup :set_jose_json_lib

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

  alias OpenIDConnect.{HTTPClientMock, MockWorker}

  describe "update_documents" do
    test "when the new documents are retrieved successfully" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      HTTPClientMock
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration" ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs" -> @google_certs end)

      expected_document =
        @google_document
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()

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
      assert remaining_lifetime == 16750
    end

    test "fails during open id configuration document with HTTPoison error" do
      config = [
        discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration"
      ]

      expect(
        HTTPClientMock,
        :get,
        fn "https://accounts.google.com/.well-known/openid-configuration" ->
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
        fn "https://accounts.google.com/.well-known/openid-configuration" ->
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
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration" ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs" ->
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
      |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration" ->
        @google_document
      end)
      |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs" ->
        {:ok, %HTTPoison.Response{status_code: 404}}
      end)

      assert OpenIDConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Response{status_code: 404}}
    end
  end

  describe "generating the authorization uri" do
    test "with default worker name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code&scope=openid+email+profile"

        assert OpenIDConnect.authorization_uri(:google) == expected
      after
        GenServer.stop(pid)
      end
    end

    test "with custom worker name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :other_openid_worker)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code&scope=openid+email+profile"

        assert OpenIDConnect.authorization_uri(:google, :other_openid_worker) == expected
      after
        GenServer.stop(pid)
      end
    end
  end

  describe "fetching tokens" do
    test "when token fetch is successful" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      config = GenServer.call(:openid_connect, {:config, :google})

      form_body = [
        client_id: config[:client_id],
        client_secret: config[:client_secret],
        code: "1234",
        grant_type: "authorization_code",
        redirect_uri: config[:redirect_uri]
      ]

      try do
        expect(HTTPClientMock, :post, fn "https://www.googleapis.com/oauth2/v4/token",
                                         {:form, ^form_body},
                                         _headers ->
          {:ok, %HTTPoison.Response{status_code: 200, body: Jason.encode!(%{})}}
        end)

        {:ok, body} = OpenIDConnect.fetch_tokens(:google, "1234")

        assert body == %{}
      after
        GenServer.stop(pid)
      end
    end

    test "when token fetch is successful with a different GenServer name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :other_openid_connect)

      config = GenServer.call(:other_openid_connect, {:config, :google})

      form_body = [
        client_id: config[:client_id],
        client_secret: config[:client_secret],
        code: "1234",
        grant_type: "authorization_code",
        redirect_uri: config[:redirect_uri]
      ]

      try do
        expect(HTTPClientMock, :post, fn "https://www.googleapis.com/oauth2/v4/token",
                                         {:form, ^form_body},
                                         _headers ->
          {:ok, %HTTPoison.Response{status_code: 200, body: Jason.encode!(%{})}}
        end)

        {:ok, body} = OpenIDConnect.fetch_tokens(:google, "1234", :other_openid_connect)

        assert body == %{}
      after
        GenServer.stop(pid)
      end
    end

    test "when token fetch fails with bad domain" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      http_error = %HTTPoison.Error{reason: :nxdomain}

      try do
        expect(HTTPClientMock, :post, fn "https://www.googleapis.com/oauth2/v4/token",
                                         {:form, _form_body},
                                         _headers ->
          {:ok, http_error}
        end)

        resp = OpenIDConnect.fetch_tokens(:google, "1234")

        assert resp == {:error, :fetch_tokens, http_error}
      after
        GenServer.stop(pid)
      end
    end

    test "when token fetch doesn't return a 200 response" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      http_error = %HTTPoison.Response{status_code: 404}

      try do
        expect(HTTPClientMock, :post, fn "https://www.googleapis.com/oauth2/v4/token",
                                         {:form, _form_body},
                                         _headers ->
          {:ok, http_error}
        end)

        resp = OpenIDConnect.fetch_tokens(:google, "1234")

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
        {jwk, []} = Code.eval_file("test/fixtures/rsa/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify(:google, token)
        assert result == {:ok, claims}
      after
        GenServer.stop(pid)
      end
    end

    test "is successful with multiple jwks" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/rsa/jwks.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk
          |> Map.get("keys")
          |> List.last()
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify(:google, token)
        assert result == {:ok, claims}
      after
        GenServer.stop(pid)
      end
    end

    test "fails with invalid token format" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/rsa/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        result = OpenIDConnect.verify(:google, "fail")
        assert result == {:error, :verify, "invalid token format"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails with invalid token claims format" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/rsa/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        token =
          [
            "fail",
            "fail",
            "fail"
          ]
          |> Enum.map(fn header -> Base.encode64(header) end)
          |> Enum.join(".")

        result = OpenIDConnect.verify(:google, token)
        assert result == {:error, :verify, "token claims did not contain a JSON payload"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails with token not including algorithm hint" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk, []} = Code.eval_file("test/fixtures/rsa/jwk1.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk)})

        token =
          [
            "{}",
            "{}",
            "{}"
          ]
          |> Enum.map(fn header -> Base.encode64(header) end)
          |> Enum.join(".")

        result = OpenIDConnect.verify(:google, token)
        assert result == {:error, :verify, "no `alg` found in token"}
      after
        GenServer.stop(pid)
      end
    end

    test "fails when verification fails" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        {jwk1, []} = Code.eval_file("test/fixtures/rsa/jwk1.exs")
        {jwk2, []} = Code.eval_file("test/fixtures/rsa/jwk2.exs")
        :ok = GenServer.call(pid, {:put, :jwk, JOSE.JWK.from(jwk1)})

        claims = %{"email" => "brian@example.com"}

        {_alg, token} =
          jwk2
          |> JOSE.JWK.from()
          |> JOSE.JWS.sign(Jason.encode!(claims), %{"alg" => "RS256"})
          |> JOSE.JWS.compact()

        result = OpenIDConnect.verify(:google, token)
        assert result == {:error, :verify, "verification failed"}
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
