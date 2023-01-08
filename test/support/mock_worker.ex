defmodule OpenIDConnect.MockWorker do
  @moduledoc """
  Mock the Worker.
  """
  use GenServer

  @google_document Fixtures.load(:google, :discovery_document)
                   |> elem(1)
                   |> Map.get(:body)
                   |> Jason.decode!()
                   |> OpenIDConnect.normalize_discovery_document()

  @google_jwk Fixtures.load(:google, :jwks)
              |> elem(1)
              |> Map.get(:body)
              |> Jason.decode!()
              |> JOSE.JWK.from()

  def init(_opts) do
    {:ok, build_state()}
  end

  defp build_state do
    {"google", config} =
      Application.get_env(:openid_connect, :providers)
      |> List.keyfind("google", 0)

    %{
      config: config,
      jwk: @google_jwk,
      document: @google_document
    }
  end

  def handle_cast({:reconfigure, state}, _state) do
    {:noreply, state}
  end

  def handle_call({:discovery_document, _provider}, _from, state) do
    {:reply, Map.get(state, :document), state}
  end

  def handle_call({:jwk, "google"}, _from, state) do
    {:reply, Map.get(state, :jwk), state}
  end

  def handle_call({:config, "google"}, _from, state) do
    {:reply, Map.get(state, :config), state}
  end

  def handle_call({:put, key, value}, _from, state) do
    {:reply, :ok, Map.put(state, key, value)}
  end

  def handle_call(_anything, _from, _state) do
    {:reply, nil, %{}}
  end
end
