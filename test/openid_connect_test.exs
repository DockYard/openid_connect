defmodule OpenidConnectTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

  alias OpenidConnect.{HTTPClientMock, MockWorker}

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

      expected_certs =
        @google_certs
        |> elem(1)
        |> Map.get(:body)
        |> Jason.decode!()

      {:ok,
       %{
         discovery_document: discovery_document,
         certs: certs,
         remaining_lifetime: remaining_lifetime
       }} = OpenidConnect.update_documents(config)

      assert expected_document == discovery_document
      assert expected_certs == certs
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

      assert OpenidConnect.update_documents(config) ==
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

      assert OpenidConnect.update_documents(config) ==
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
        {:ok, %HTTPoison.Error{id: nil, reason: :nxdomain}}
      end)

      assert OpenidConnect.update_documents(config) ==
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

      assert OpenidConnect.update_documents(config) ==
               {:error, :update_documents, %HTTPoison.Response{status_code: 404}}
    end
  end

  describe "generating the authorization uri" do
    test "with default worker name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :openid_connect)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code&scope=openid+email+profile"

        assert OpenidConnect.authorization_uri(:google) == expected
      after
        GenServer.stop(pid)
      end
    end

    test "with custom worker name" do
      {:ok, pid} = GenServer.start_link(MockWorker, [], name: :other_openid_worker)

      try do
        expected =
          "https://accounts.google.com/o/oauth2/v2/auth?client_id=CLIENT_ID_1&redirect_uri=https%3A%2F%2Fdev.example.com%3A4200%2Fsession&response_type=code&scope=openid+email+profile"

        assert OpenidConnect.authorization_uri(:google, :other_openid_worker) == expected
      after
        GenServer.stop(pid)
      end
    end
  end

  describe "fetching tokens" do
    test "when token fetch is successful" do
    end

    test "when token fetch fails" do
    end
  end

  describe "jwt verification" do
    test "is successful" do
    end

    test "fails" do
    end
  end
end
