defmodule OpenidConnect.Worker do
  use GenServer

  require Logger

  @refresh_time 60 * 60 * 1000

  def start_link(provider_configs, name \\ :openid_connect) do
    GenServer.start_link(__MODULE__, provider_configs, name: name)
  end

  def init(:ignore) do
    :ignore
  end

  def init(provider_configs) do
    state = Enum.into(provider_configs, %{}, fn({provider, config}) ->
      Process.send_after(self(), {:update_documents, provider}, 1_000)
      {provider, %{config: config, documents: %{}}}
    end)

    {:ok, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    discovery_document = get_in(state, [provider, :documents, :discovery_document])
    {:reply, discovery_document, state}
  end

  def handle_call({:certs, provider}, _from, state) do
    certs = get_in(state, [provider, :documents, :certs])
    {:reply, certs, state}
  end

  def handle_call({:config, provider}, _from, state) do
    config = get_in(state, [provider, :config])
    {:reply, config, state}
  end

  def handle_info({:update_documents, provider}, state) do
    Logger.info(fn -> "Updating OpenID Connect documents for #{provider}" end)

    config = get_in(state, [provider, :config])

    %{remaining_lifetime: remaining_lifetime} = documents = OpenidConnect.update_documents(config)
    state = put_in(state, [provider, :documents], documents)

    refresh_time = time_until_next_refresh(remaining_lifetime)

    Process.send_after(self(), :update_documents, refresh_time)

    {:noreply, state}
  end

  defp time_until_next_refresh(nil), do: @refresh_time
  defp time_until_next_refresh(time_in_seconds) when time_in_seconds > 0, do: :timer.seconds(time_in_seconds)
  defp time_until_next_refresh(time_in_seconds) when time_in_seconds <= 0, do: 0
end
