defmodule OpenidConnect.MockWorker do
  use GenServer

  @google_document Fixtures.load(:google, :discovery_document)
                   |> elem(1)
                   |> Map.get(:body)
                   |> Jason.decode!()

  @google_certs Fixtures.load(:google, :certs)
                |> elem(1)
                |> Map.get(:body)
                |> Jason.decode!()

  def init(_) do
    config =
      Application.get_env(:openid_connect, :providers)
      |> Keyword.get(:google)

    {:ok,
     %{
       config: config,
       certs: @google_certs,
       document: @google_document
     }}
  end

  def handle_call({:discovery_document, :google}, _from, state) do
    {:reply, Map.get(state, :document), state}
  end

  def handle_call({:certs, :google}, _from, state) do
    {:reply, Map.get(state, :certs), state}
  end

  def handle_call({:config, :google}, _from, state) do
    {:reply, Map.get(state, :config), state}
  end

  def handle_call({:put, key, value}, _from, state) do
    {:reply, :ok, Map.put(state, key, value)}
  end

  def handle_call(_anything, _from, _state) do
    {:reply, nil, %{}}
  end
end
