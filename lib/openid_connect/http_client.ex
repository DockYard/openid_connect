defmodule OpenidConnect.HTTPClient do
  @moduledoc false
  @behaviour OpenidConnect.HTTPClientBehaviour

  def get(url, headers \\ [], options \\ []) do
    HTTPoison.get(url, headers, options)
  end

  def post(url, body, headers \\ [], options \\ []) do
    HTTPoison.post(url, body, headers, options)
  end
end
