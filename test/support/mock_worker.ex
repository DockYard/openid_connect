defmodule OpenIDConnect.MockWorker do
  use GenServer

  @google_document Fixtures.load(:google, :discovery_document)
                   |> elem(1)
                   |> Map.get(:body)
                   |> Jason.decode!()
                   |> OpenIDConnect.normalize_discovery_document()

  @google_jwk Fixtures.load(:google, :certs)
              |> elem(1)
              |> Map.get(:body)
              |> Jason.decode!()
              |> JOSE.JWK.from()

  def init(_) do
    state =
      Application.get_env(:openid_connect, :providers)
      |> Enum.into(%{}, fn {provider, config} ->
        documents = %{
          discovery_document: @google_document,
          jwk: @google_jwk
        }

        {provider, %{config: config, documents: documents}}
      end)

    {:ok, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    {:reply, get_in(state, [provider, :documents, :discovery_document]), state}
  end

  def handle_call({:jwk, provider}, _from, state) do
    {:reply, get_in(state, [provider, :documents, :jwk]), state}
  end

  def handle_call({:config, provider}, _from, state) do
    {:reply, get_in(state, [provider, :config]), state}
  end

  def handle_call({:put, provider, key, value}, _from, state) do
    state = put_in(state, [provider, :documents, key], value)
    {:reply, :ok, state}
  end

  def handle_call(_anything, _from, _state) do
    {:reply, nil, %{}}
  end
end
