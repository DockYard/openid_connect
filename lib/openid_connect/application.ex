defmodule OpenIDConnect.Application do
  use Application

  def start(_type, _args) do
    opts = [strategy: :one_for_one, name: FzVpn.Supervisor]
    Supervisor.start_link(children(), opts)
  end

  def children do
    [
      {Finch,
       name: OpenIDConnect.Finch,
       pools: %{
         default: pool_opts()
       }},
      OpenIDConnect.Document.Cache
    ]
  end

  defp pool_opts do
    transport_opts = Application.get_env(:openid_connect, :finch_transport_opts, [])
    [conn_opts: [transport_opts: transport_opts]]
  end
end
