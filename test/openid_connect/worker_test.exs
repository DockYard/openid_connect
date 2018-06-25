defmodule OpenidConnect.WorkerTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

  alias OpenidConnect.{HTTPClientMock}

  test "starting with :ignore does nothing" do
    :ignore = OpenidConnect.Worker.start_link(:ignore)
  end

  test "starting with a single provider will retrieve the necessary documents" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenidConnect.Worker, config})

    state = :sys.get_state(pid)

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

    assert expected_document == get_in(state, [:google, :documents, :discovery_document])
    assert expected_certs == get_in(state, [:google, :documents, :certs])
  end

  test "worker can respond to a call for the config" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenidConnect.Worker, config})

    google_config = GenServer.call(pid, {:config, :google})

    assert get_in(config, [:google]) == google_config
  end

  test "worker can respond to a call for a provider's discovery document" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenidConnect.Worker, config})

    discovery_document = GenServer.call(pid, {:discovery_document, :google})

    expected_document =
      @google_document
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()

    assert expected_document == discovery_document
  end

  test "worker can respond to a call for a provider's certs" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenidConnect.Worker, config})

    certs = GenServer.call(pid, {:certs, :google})

    expected_certs =
      @google_certs
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()

    assert expected_certs == certs
  end

  defp mock_http_requests() do
    HTTPClientMock
    |> expect(:get, fn("https://accounts.google.com/.well-known/openid-configuration") -> @google_document end)
    |> expect(:get, fn("https://www.googleapis.com/oauth2/v3/certs") -> @google_certs end)
  end
end
