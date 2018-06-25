defmodule OpenidConnect.HTTPClientBehaviour do
  @moduledoc false

  alias HTTPoison.{Response, AsyncResponse, Error}

  @type headers :: [{atom, binary}] | [{binary, binary}] | %{binary => binary}

  @callback get(binary) :: {:ok, Response.t | AsyncResponse.t} | {:error, Error.t}
  @callback get(binary, headers, Keyword.t) :: {:ok, Response.t | AsyncResponse.t} | {:error, Error.t}

  @callback post(binary, any) :: {:ok, Response.t | AsyncResponse.t} | {:error, Error.t}
  @callback post(binary, any, headers, Keyword.t) :: {:ok, Response.t | AsyncResponse.t} | {:error, Error.t}
end
