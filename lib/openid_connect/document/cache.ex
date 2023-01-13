defmodule OpenIDConnect.Document.Cache do
  use GenServer
  alias OpenIDConnect.Document

  @max_size Application.compile_env(:openid_connect, :document_cache_max_size, 1_000)

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def init(_opts) do
    Process.send_after(self(), :gc, :timer.minutes(1))
    {:ok, %{}}
  end

  def put(pid \\ __MODULE__, uri, document) do
    GenServer.cast(pid, {:put, uri, document})
  end

  def fetch(pid \\ __MODULE__, uri) do
    GenServer.call(pid, {:fetch, uri})
  end

  def flush(pid \\ __MODULE__) do
    GenServer.call(pid, :flush)
  end

  def handle_cast({:put, uri, document}, state) do
    if document_expired?(document) do
      {:noreply, state}
    else
      expires_in_seconds = expires_in_seconds(document.expires_at)
      timer_ref = Process.send_after(self(), {:remove, uri}, :timer.seconds(expires_in_seconds))
      state = Map.put(state, uri, {timer_ref, DateTime.utc_now(), document})
      {:noreply, state}
    end
  end

  def handle_call(:flush, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:fetch, uri}, _from, state) do
    case Map.fetch(state, uri) do
      {:ok, {timer_ref, _last_fetched_at, document}} ->
        if document_expired?(document) do
          state = Map.delete(state, uri)
          {:reply, :error, state}
        else
          state = Map.put(state, uri, {timer_ref, DateTime.utc_now(), document})
          {:reply, {:ok, document}, state}
        end

      :error ->
        {:reply, :error, state}
    end
  end

  def handle_info({:remove, uri}, state) do
    {:noreply, Map.delete(state, uri)}
  end

  def handle_info(:gc, state) do
    state =
      if Enum.count(state) > @max_size do
        state
        |> Enum.sort_by(
          fn {_key, {_ref, last_fetched_at, _document}} -> last_fetched_at end,
          {:desc, DateTime}
        )
        |> Enum.take(@max_size)
        |> Enum.into(%{})
      else
        state
      end

    Process.send_after(self(), :gc, :timer.minutes(1))

    {:noreply, state}
  end

  defp expires_in_seconds(%DateTime{} = datetime) do
    max(DateTime.diff(datetime, DateTime.utc_now(), :second), 0)
  end

  defp document_expired?(%Document{expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) != :gt
  end
end
