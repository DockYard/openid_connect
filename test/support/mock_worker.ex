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
    {:ok, %{}}
  end

  def handle_call({:discovery_document, :google}, _from, _state) do
    {:reply, @google_document, %{}}
  end

  def handle_call({:certs, :google}, _from, _state) do
    {:reply, @google_certs, %{}}
  end

  def handle_call({:config, :google}, _from, _state) do
    config =
      Application.get_env(:openid_connect, :providers)
      |> Keyword.get(:google)

    {:reply, config, %{}}
  end

  def handle_call(_anything, _from, _state) do
    {:reply, nil, %{}}
  end
end
