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
    {:ok, []}
  end

  def init(provider_configs) do
    {:ok, build_state(provider_configs)}
  end

  defp build_state(provider_configs) do
    Enum.into(provider_configs, %{}, fn {provider, config} ->
      documents = update_documents(provider, config)
      {provider, %{config: config, documents: documents}}
    end)
  end

  def handle_call(:flush, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    provider = Map.fetch!(state, provider)
    discovery_document = provider.documents.discovery_document
    {:reply, discovery_document, state}
  end

  def handle_call({:jwk, provider}, _from, state) do
    provider = Map.fetch!(state, provider)
    jwk = provider.documents.jwk
    {:reply, jwk, state}
  end

  def handle_call({:config, provider}, _from, state) do
    provider = Map.fetch!(state, provider)
    config = provider.config
    {:reply, config, state}
  end

  def handle_cast({:reconfigure, provider_configs}, _state) do
    {:noreply, build_state(provider_configs)}
  end

  def handle_info({:update_documents, provider}, state) do
    provider = Map.fetch!(state, provider)
    config = provider.config
    documents = update_documents(provider, config)
    state = Map.put(state, provider, %{provider | documents: documents})
    {:noreply, state}
  end

  defp update_documents(provider, config) do
    {:ok, %{remaining_lifetime: remaining_lifetime} = documents} =
      OpenIDConnect.update_documents(config)

    refresh_time = time_until_next_refresh(remaining_lifetime)

    Process.send_after(self(), {:update_documents, provider}, refresh_time)

    documents
  end

  defp time_until_next_refresh(nil), do: @refresh_time

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds > 0,
    do: :timer.seconds(time_in_seconds)

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds <= 0, do: 0
end
