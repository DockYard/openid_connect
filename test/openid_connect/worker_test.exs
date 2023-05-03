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

  test "starting with a single provider will retrieve the necessary documents" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    state = :sys.get_state(pid)

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

    assert expected_document == get_in(state, [:google, :documents, :discovery_document])
    assert expected_jwk == get_in(state, [:google, :documents, :jwk])
  end

  test "worker can respond to a call for the config" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    google_config = GenServer.call(pid, {:config, :google})

    assert get_in(config, [:google]) == google_config
  end

  test "worker started using callback function can respond to a call for the config" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, {:callback, fn ->
      config
    end}})

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

  test "worker can start without internet connectivity, initialization is deferred" do
    mock_http_internet_down()

    config = Application.get_env(:openid_connect, :providers)
    {:error, :update_documents, _} = OpenIDConnect.update_documents(config)

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})
    catch_exit(GenServer.call(pid, {:jwk, :google}))
  end

  defp mock_http_requests do
    HTTPClientMock
    |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration", _headers, _opts ->
      @google_document
    end)
    |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, _opts -> @google_certs end)
  end

  defp mock_http_internet_down do
    HTTPClientMock
    |> expect(:get, fn _, _, _ ->
      {:error, %HTTPoison.Error{id: nil, reason: :nxdomain}}
    end)
    |> expect(:get, fn _, _, _ ->
      {:error, %HTTPoison.Error{id: nil, reason: :nxdomain}}
    end)
  end
end
