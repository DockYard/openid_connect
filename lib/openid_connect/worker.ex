defmodule OpenIDConnect.Worker do
  use GenServer

  @moduledoc """
  Worker module for OpenID Connect

  This worker will store and periodically update each provider's documents and JWKs according to the lifetimes
  """

  @refresh_time 60 * 60 * 1000

  def start_link(provider_configs, name \\ :openid_connect) do
    GenServer.start_link(__MODULE__, provider_configs, name: name)
  end

  def init(:ignore) do
    :ignore
  end

  def init(provider_configs) do
    state =
      Enum.into(provider_configs, %{}, fn {provider, config} ->
        documents =
          case update_documents(provider, config) do
            {:ok, documents} -> documents
            _ -> nil
          end
        {provider, %{config: config, documents: documents}}
      end)

    {:ok, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    case get_in(state, [provider, :documents, :discovery_document]) do
      nil ->
        config = get_in(state, [provider, :config])
        case update_documents(provider, config) do
          {:ok, %{discovery_document: discovery_document} = documents} ->
            put_in(state, [provider, :documents], documents)
            {:reply, {:ok, discovery_document}, state}

          error ->
            {:reply, error, state}
        end

      discovery_document ->
        {:reply, {:ok, discovery_document}, state}
    end
  end

  def handle_call({:jwk, provider}, _from, state) do
    jwk = get_in(state, [provider, :documents, :jwk])
    {:reply, jwk, state}
  end

  def handle_call({:config, provider}, _from, state) do
    config = get_in(state, [provider, :config])
    {:reply, config, state}
  end

  def handle_info({:update_documents, provider}, state) do
    config = get_in(state, [provider, :config])

    state =
      case update_documents(provider, config) do
        {:ok, documents} ->
          put_in(state, [provider, :documents], documents)

        _ ->
          state
      end

    {:noreply, state}
  end

  defp update_documents(provider, config) do
    case OpenIDConnect.update_documents(config) do
      {:ok, %{remaining_lifetime: remaining_lifetime} = documents} ->
        refresh_time = time_until_next_refresh(remaining_lifetime)

        Process.send_after(self(), {:update_documents, provider}, refresh_time)

        {:ok, documents}

      error ->
        Process.send_after(self(), {:update_documents, provider}, @refresh_time)
        error
    end
  end

  defp time_until_next_refresh(nil), do: @refresh_time

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds > 0,
    do: :timer.seconds(time_in_seconds)

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds <= 0, do: 0
end
