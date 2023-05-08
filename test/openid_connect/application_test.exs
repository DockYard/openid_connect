defmodule OpenIDConnect.ApplicationTest do
  use ExUnit.Case, async: true
  import OpenIDConnect.Application

  test "allows to override Finch transport options" do
    assert children() == [
             {Finch,
              [name: OpenIDConnect.Finch, pools: %{default: [conn_opts: [transport_opts: []]]}]},
             OpenIDConnect.Document.Cache
           ]

    transport_opts = [cacertfile: "foo.pem"]
    Application.put_env(:openid_connect, :finch_transport_opts, transport_opts)

    assert children() == [
             {Finch,
              [
                name: OpenIDConnect.Finch,
                pools: %{default: [conn_opts: [transport_opts: transport_opts]]}
              ]},
             OpenIDConnect.Document.Cache
           ]

    Application.put_env(:openid_connect, :finch_transport_opts, [])
  end
end
