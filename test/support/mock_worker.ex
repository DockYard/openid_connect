defmodule OpenidConnect.MockWorker do
  use GenServer

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

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
    {:reply, %{}}
  end
end
