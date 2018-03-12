defmodule OpenidConnect do
  require Logger

  def discovery_document(provider) do
    GenServer.call(:openid_connect, {:discovery_document, provider})
  end

  def certs(provider) do
    GenServer.call(:openid_connect, {:certs, provider})
  end

  def authorization_uri(provider) do
    doc = discovery_document(provider)

    uri = Map.get(doc, "authorization_endpoint")
    params = %{
      client_id: client_id(provider),
      redirect_uri: redirect_uri(provider),
      response_type: "code",
      scope: "openid email profile"
    }

    build_uri(uri, params)
  end

  def access_token_uri(provider) do
    Map.get(discovery_document(provider), "token_endpoint")
  end

  def fetch_tokens(provider, params) do
    uri = access_token_uri(provider)

    form_body = [
      client_id: client_id(provider),
      client_secret: client_secret(provider),
      code: params["code"],
      grant_type: "authorization_code",
      redirect_uri: redirect_uri(provider)
    ]

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    with {:ok, resp} <- HTTPoison.post(uri, {:form, form_body}, headers),
         {:ok, json} <- Poison.decode(resp.body),
         {:ok, json} <- assert_json(json) do
      {:ok, json}
    else
      error ->
        Logger.error(inspect(error))
        {:error, :fetch_failed}
    end
  end

  def verify(provider, jwt) do
    jwk_set = JOSE.JWK.from(certs(provider))

    alg =
      with [header, _, _] <- String.split(jwt, "."),
           {:ok, header} <- Base.decode64(header, padding: false),
           {:ok, header} <- Poison.decode(header), do: Map.get(header, "alg")

    results = for jwk <- elem(jwk_set.keys, 1) do
      {
        JOSE.JWK.from(jwk).fields["kid"],
        JOSE.JWS.verify_strict(jwk, [alg], jwt)
      }
    end

    Enum.find_value(results, {:error, :verification_failed}, fn
      {_, {true, claims, _}} -> Poison.decode(claims)
      _ -> false
    end)
  end

  def client_id(provider) do
    Keyword.get(config(provider), :client_id)
  end

  def client_secret(provider) do
    Keyword.get(config(provider), :client_secret)
  end

  def redirect_uri(provider) do
    Keyword.get(config(provider), :redirect_uri)
  end

  def discovery_document_uri(provider) do
    Keyword.get(config(provider), :discovery_document_uri)
  end

  defp config(provider) do
    :openid_connect
    |> Application.get_env(:provider)
    |> Keyword.get(provider)
  end

  def update_documents() do
    :openid_connect
    |> Application.get_env(:provider)
    |> Keyword.keys()
    |> Enum.reduce([], fn(provider, provider_documents) ->
      {:ok, discovery_document, _} = fetch_resource(discovery_document_uri(provider))
      {:ok, certs, remaining_lifetime} = fetch_resource(discovery_document["jwks_uri"])

      documents = %{discovery_document: discovery_document, certs: certs, remaining_lifetime: remaining_lifetime}

      Keyword.put(provider_documents, provider, documents)
    end)
  end

  defp fetch_resource(uri) do
    with {:ok, resp} <- HTTPoison.get(uri),
         {:ok, json} <- Poison.decode(resp.body),
         {:ok, json} <- assert_json(json) do
      {:ok, json, remaining_lifetime(resp.headers)}
    else
      _ -> {:error, :fetch_failed}
    end
  end

  defp build_uri(uri, params) do
    query = URI.encode_query(params)

    uri
    |> URI.merge("?#{query}")
    |> URI.to_string()
  end


  defp assert_json(%{"error" => reason}), do: {:error, reason}
  defp assert_json(json), do: {:ok, json}

  @spec remaining_lifetime([{String.t, String.t}]) :: integer | nil
  defp remaining_lifetime(headers) do
    with headers = Enum.into(headers, %{}),
         {:ok, max_age} <- find_max_age(headers),
         {:ok, age} <- find_age(headers) do
      max_age - age
    else
      _ -> nil
    end
  end

  defp find_max_age(headers) when is_map(headers) do
    case Regex.run(~r"(?<=max-age=)\d+", Map.get(headers, "Cache-Control", "")) do
      [max_age] -> {:ok, String.to_integer(max_age)}
      _ -> :error
    end
  end

  def find_age(headers) when is_map(headers) do
    case Map.get(headers, "Age") do
      nil -> :error
      age -> {:ok, String.to_integer(age)}
    end
  end
end
