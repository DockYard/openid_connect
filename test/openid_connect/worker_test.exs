defmodule OpenIDConnect.WorkerTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

  alias OpenIDConnect.{HTTPClientMock}

  test "starting with :ignore does nothing" do
    :ignore = OpenIDConnect.Worker.start_link(:ignore)
  end

  test "starting with a all providers will retrieve the necessary documents" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    state = :sys.get_state(pid)

    expected_doc =
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

    assert expected_doc == get_in(state, [:google, :documents, :discovery_document])
    assert expected_jwk == get_in(state, [:google, :documents, :jwk])
    assert expected_doc == get_in(state, [:google_auth_basic, :documents, :discovery_document])
    assert expected_jwk == get_in(state, [:google_auth_basic, :documents, :jwk])
  end

  test "worker can respond to a call for the config" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    google_config = GenServer.call(pid, {:config, :google})

    assert get_in(config, [:google]) == google_config
  end

  test "worker can respond to a call for a provider's discovery document" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    discovery_document = GenServer.call(pid, {:discovery_document, :google})

    expected_document =
      @google_document
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> OpenIDConnect.normalize_discovery_document()

    assert expected_document == discovery_document
  end

  test "worker can respond to a call for a provider's jwk" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    jwk = GenServer.call(pid, {:jwk, :google})

    expected_jwk =
      @google_certs
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> JOSE.JWK.from()

    assert expected_jwk == jwk
  end

  defp mock_http_requests do
    discovery_document_uri = "https://accounts.google.com/.well-known/openid-configuration"
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"

    HTTPClientMock
    |> expect(:get, fn ^discovery_document_uri, _headers, _opts -> @google_document end)
    |> expect(:get, fn ^jwks_uri, _headers, _opts -> @google_certs end)
    |> expect(:get, fn ^discovery_document_uri, _headers, _opts -> @google_document end)
    |> expect(:get, fn ^jwks_uri, _headers, _opts -> @google_certs end)
  end
end
