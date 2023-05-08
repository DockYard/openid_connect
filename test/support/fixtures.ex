defmodule OpenIDConnect.Fixtures do
  def start_fixture(provider, overrides \\ %{}) do
    bypass = Bypass.open()
    endpoint = "http://localhost:#{bypass.port}/"
    {jwks, overrides} = Map.pop(overrides, "jwks")

    Bypass.expect_once(bypass, "GET", "/.well-known/jwks.json", fn conn ->
      {status_code, body, headers} = load_fixture(provider, "jwks")
      body = if jwks, do: jwks, else: body
      send_response(conn, status_code, body, headers)
    end)

    Bypass.expect_once(bypass, "GET", "/.well-known/discovery-document.json", fn conn ->
      {status_code, body, headers} = load_fixture(provider, "discovery_document")
      body = Map.merge(body, %{"jwks_uri" => "#{endpoint}.well-known/jwks.json"})
      body = Map.merge(body, overrides)
      send_response(conn, status_code, body, headers)
    end)

    {bypass, "#{endpoint}.well-known/discovery-document.json"}
  end

  def load_fixture(provider, type) do
    {%{status_code: status_code, body: body, headers: headers}, _} =
      Code.eval_file("test/fixtures/http/#{provider}/#{type}.exs")

    {status_code, body, headers}
  end

  def send_response(conn, status_code, body, headers) do
    headers
    |> Enum.reduce(conn, fn {key, value}, conn ->
      Plug.Conn.put_resp_header(conn, key, value)
    end)
    |> Plug.Conn.resp(status_code, Jason.encode!(body))
  end
end
