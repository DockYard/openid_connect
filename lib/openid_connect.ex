defmodule OpenidConnect do
  def authorization_uri(provider, name \\ :openid_connect) do
    document = discovery_document(provider, name)
    config = config(provider, name)

    uri = Map.get(document, "authorization_endpoint")

    params = %{
      client_id: client_id(config),
      redirect_uri: redirect_uri(config),
      response_type: "code",
      scope: normalize_scope(provider, config[:scope])
    }

    build_uri(uri, params)
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

    with {:ok, %HTTPoison.Response{status_code: status_code} = resp} when status_code in 200..299 <-
           http_client().post(uri, {:form, form_body}, headers),
         {:ok, json} <- Jason.decode(resp.body),
         {:ok, json} <- assert_json(json) do
      {:ok, json}
    else
      {:ok, resp} -> {:error, :fetch_tokens, resp}
      {:error, reason} -> {:error, :fetch_tokens, reason}
    end
  end

  def verify(provider, jwt, name \\ :openid_connect) do
    jwk =
      provider
      |> certs(name)
      |> JOSE.JWK.from()

    with {:ok, protected} <- peek_protected(jwt),
         {:ok, decoded_protected} <- Jason.decode(protected),
         {:ok, token_alg} <- Map.fetch(decoded_protected, "alg"),
         {true, claims, _jwk} <- do_verify(jwk, token_alg, jwt) do
      Jason.decode(claims)
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :verify, "token claims did not contain a JSON payload"}

      {:error, :peek_protected} ->
        {:error, :verify, "invalid token format"}

      :error ->
        {:error, :verify, "no `alg` found in token"}

      {false, _claims, _jwk} ->
        {:error, :verify, "verification failed"}
    end
  end

  defp peek_protected(jwt) do
    try do
      {:ok, JOSE.JWS.peek_protected(jwt)}
    rescue
      _ -> {:error, :peek_protected}
    end
  end

  defp do_verify(%JOSE.JWK{keys: {:jose_jwk_set, jwks}}, token_alg, jwt) do
    Enum.find_value(jwks, {false, "{}", jwt}, fn jwk ->
      jwk
      |> JOSE.JWK.from()
      |> do_verify(token_alg, jwt)
      |> case do
        {false, _claims, _jwt} -> false
        verified_claims -> verified_claims
      end
    end)
  end

  defp do_verify(%JOSE.JWK{} = jwk, token_alg, jwt),
    do: JOSE.JWS.verify_strict(jwk, [token_alg], jwt)

  def update_documents(config) do
    uri = discovery_document_uri(config)

    with {:ok, discovery_document, _} <- fetch_resource(uri),
         {:ok, certs, remaining_lifetime} <- fetch_resource(discovery_document["jwks_uri"]) do
      {:ok,
       %{
         discovery_document: discovery_document,
         certs: certs,
         remaining_lifetime: remaining_lifetime
       }}
    else
      {:error, reason} -> {:error, :update_documents, reason}
    end
  end

  defp discovery_document(provider, name) do
    GenServer.call(name, {:discovery_document, provider})
  end

  defp certs(provider, name) do
    GenServer.call(name, {:certs, provider})
  end

  defp config(provider, name) do
    GenServer.call(name, {:config, provider})
  end

  defp access_token_uri(provider, name) do
    Map.get(discovery_document(provider, name), "token_endpoint")
  end

  defp client_id(config) do
    Keyword.get(config, :client_id)
  end

  defp client_secret(config) do
    Keyword.get(config, :client_secret)
  end

  defp redirect_uri(config) do
    Keyword.get(config, :redirect_uri)
  end

  defp discovery_document_uri(config) do
    Keyword.get(config, :discovery_document_uri)
  end

  defp fetch_resource(uri) do
    with {:ok, %HTTPoison.Response{status_code: status_code} = resp} when status_code in 200..299 <-
           http_client().get(uri),
         {:ok, json} <- Jason.decode(resp.body),
         {:ok, json} <- assert_json(json) do
      {:ok, json, remaining_lifetime(resp.headers)}
    else
      {:ok, resp} -> {:error, resp}
      error -> error
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

  @spec remaining_lifetime([{String.t(), String.t()}]) :: integer | nil
  defp remaining_lifetime(headers) do
    with headers = Enum.into(headers, %{}),
         {:ok, max_age} <- find_max_age(headers),
         {:ok, age} <- find_age(headers) do
      max_age - age
    else
      _ -> nil
    end
  end

  defp normalize_scope(provider, scopes) when is_nil(scopes) or scopes == [] do
    raise ArgumentError, "no scopes have been defined for provider `#{provider}`"
  end

  defp normalize_scope(_provider, scopes) when is_binary(scopes), do: scopes
  defp normalize_scope(_provider, scopes) when is_list(scopes), do: Enum.join(scopes, " ")

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

  defp http_client do
    Application.get_env(:openid_connect, :http_client, HTTPoison)
  end
end
