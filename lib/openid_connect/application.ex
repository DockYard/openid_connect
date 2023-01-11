defmodule OpenIDConnect.Application do
  use Application

  def start(_type, _args) do
    opts = [strategy: :one_for_one, name: FzVpn.Supervisor]
    Supervisor.start_link(children(), opts)
  end

  defp children do
    [
      {Finch, name: OpenIDConnect.Finch},
      OpenIDConnect.Document.Cache
    ]
  end
end
