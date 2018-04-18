defmodule OpenidConnect do
  require Logger

  def discovery_document(provider, name \\ :openid_connect) do
    GenServer.call(name, {:discovery_document, provider})
  end

  def certs(provider, name \\ :openid_connect) do
    GenServer.call(name, {:certs, provider})
  end

  defp config(provider, name) do
    GenServer.call(name, {:config, provider})
  end

  def authorization_uri(provider, name \\ :openid_connect) do
    doc = discovery_document(provider, name)
    config = config(provider, name)

    uri = Map.get(doc, "authorization_endpoint")
    params = %{
      client_id: client_id(config),
      redirect_uri: redirect_uri(config),
      response_type: "code",
      scope: "openid email profile"
    }

    build_uri(uri, params)
  end

  def access_token_uri(provider, name) do
    Map.get(discovery_document(provider, name), "token_endpoint")
  end

  def fetch_tokens(provider, params, name \\ :openid_connect) do
    uri = access_token_uri(provider, name)
    config = config(provider, name)

    form_body = [
      client_id: client_id(config),
      client_secret: client_secret(config),
      code: params["code"],
      grant_type: "authorization_code",
      redirect_uri: redirect_uri(config)
    ]

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    with {:ok, resp} <- http_client().post(uri, {:form, form_body}, headers),
         {:ok, json} <- Poison.decode(resp.body),
         {:ok, json} <- assert_json(json) do
      {:ok, json}
    else
      error ->
        Logger.error(inspect(error))
        {:error, :fetch_failed}
    end
  end

  def verify(provider, jwt, name \\ :openid_connect) do
    jwk_set = JOSE.JWK.from(certs(provider, name))

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

  def client_id(config) do
    Keyword.get(config, :client_id)
  end

  def client_secret(config) do
    Keyword.get(config, :client_secret)
  end

  def redirect_uri(config) do
    Keyword.get(config, :redirect_uri)
  end

  def discovery_document_uri(config) do
    Keyword.get(config, :discovery_document_uri)
  end

  def update_documents(config) do
    {:ok, discovery_document, _} =
      config
      |> discovery_document_uri()
      |> fetch_resource()

    {:ok, certs, remaining_lifetime} = fetch_resource(discovery_document["jwks_uri"])

    %{discovery_document: discovery_document, certs: certs, remaining_lifetime: remaining_lifetime}
  end

  defp fetch_resource(uri) do
    with {:ok, resp} <- http_client().get(uri),
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

  defp find_age(headers) when is_map(headers) do
    case Map.get(headers, "Age") do
      nil -> :error
      age -> {:ok, String.to_integer(age)}
    end
  end

  defp http_client() do
    Application.get_env(:openid_connect, :http_client, HTTPoison)
  end
end
