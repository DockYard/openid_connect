defmodule OpenidConnect.Worker do
  use GenServer

  require Logger

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
    Logger.info(fn -> "Updating OpenID Connect provider documents" end)

    state = OpenidConnect.update_documents()
    refresh_time = time_until_next_refresh(state)

    Process.send_after(self(), :update_documents, refresh_time)

    {:noreply, state}
  end

  defp time_until_next_refresh(provider_documents) do
    provider_documents
    |> Enum.map(fn {_, %{remaining_lifetime: remaining_lifetime}} -> remaining_lifetime end)
    |> Enum.reject(&is_nil(&1))
    |> Enum.sort()
    |> Enum.at(0)
    |> case do
      nil -> @refresh_time
      time_in_seconds when time_in_seconds > 0 -> :timer.seconds(time_in_seconds)
      time_in_seconds when time_in_seconds <= 0 -> 0
    end
  end
end
