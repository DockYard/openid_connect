defmodule OpenIDConnect.Worker do
  use GenServer

  @moduledoc """
  Worker module for OpenID Connect

  This worker will store and periodically update each provider's documents and JWKs according to the lifetimes
  """

  @refresh_time 60 * 60 * 1000

  require Logger

  def start_link(options, name \\ :openid_connect)

  def start_link(config, name) do
    GenServer.start_link(__MODULE__, config, name: name)
  end

  def init(:ignore) do
    :ignore
  end

  def init({provider_configs, pid}) when is_pid(pid) do
    {:ok, state} = init(provider_configs)
    Process.send_after(pid, :ready, 1)
    {:ok, state}
  end

  def init(provider_configs) do
    state =
      Enum.into(provider_configs, %{}, fn {provider, config} ->
        Process.send_after(self(), {:update_documents, provider}, 0)
        {provider, %{config: config, documents: nil}}
      end)

    {:ok, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    discovery_document = get_in(state, [provider, :documents, :discovery_document])
    {:reply, discovery_document, state}
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
    with config <- get_in(state, [provider, :config]),
         {:ok, documents} <- update_documents(provider, config) do
      {:noreply, put_in(state, [provider, :documents], documents)}
    else
      _ -> {:noreply, state}
    end
  end

  defp update_documents(provider, config) do
    with {:ok, documents} <- OpenIDConnect.update_documents(config),
         remaining_lifetime <- Map.get(documents, :remaining_lifetime),
         refresh_time <- time_until_next_refresh(remaining_lifetime) do
      Process.send_after(self(), {:update_documents, provider}, refresh_time)
      {:ok, documents}
    else
      {:error, :update_documents, reason} = error ->
        Logger.warn("Failed to update documents for provider #{provider}: #{message(reason)}")
        Process.send_after(self(), {:update_documents, provider}, @refresh_time)
        error
    end
  end

  defp message(reason) do
    if Exception.exception?(reason) do
      Exception.message(reason)
    else
      "#{inspect(reason)}"
    end
  end

  defp time_until_next_refresh(nil), do: @refresh_time

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds > 0,
    do: :timer.seconds(time_in_seconds)

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds <= 0, do: 0
end
