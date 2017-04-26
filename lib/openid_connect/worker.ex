require OpenidConnect

defmodule OpenidConnect.Worker do
  use GenServer

  @refresh_time 60 * 60 * 1000

  def start_link(env) do
    GenServer.start_link(__MODULE__, env, name: :openid_connect)
  end

  def init(:ignore) do
    :ignore
  end

  def init(_opts) do
    Process.send_after(:openid_connect, :update_documents, 1_000)

    {:ok, []}
  end

  def handle_call({:discovery_document, provider}, _from, provider_documents) do
    discovery_document =
      provider_documents
      |> Keyword.get(provider)
      |> Map.get(:discovery_document)

    {:reply, discovery_document, provider_documents}
  end

  def handle_call({:certs, provider}, _from, provider_documents) do
    certs =
      provider_documents
      |> Keyword.get(provider)
      |> Map.get(:certs)

    {:reply, certs, provider_documents}
  end

  def handle_info(:update_documents, _state) do
    state = OpenidConnect.update_documents()

    Process.send_after(:update_documents, state, @refresh_time)
    {:noreply, state}
  end
end
