defmodule OpenIDConnect do
  @moduledoc """
  Handles a majority of the life-cycle concerns with [OpenID Connect](http://openid.net/connect/)
  """

  @typedoc """
  URI as a string
  """
  @type uri :: String.t()

  @typedoc """
  JSON Web Token

  See: https://jwt.io/introduction/
  """
  @type jwt :: String.t()

  @typedoc """
  The code returned by an OpenID Connect provider during the redirect
  """
  @type code :: String.t()

  @typedoc """
  The provider name as an atom

  Example: `:google`

  This atom should match what you've used in your application config
  """
  @type provider :: atom

  @typedoc """
  The payload of user data from the provider
  """
  @type claims :: map

  @typedoc """
  The name of the genserver

  This is optional and will default to `:openid_connect` unless overridden
  """
  @type name :: atom

  @typedoc """
  Query param map
  """
  @type params :: map

  @typedoc """
  The success tuple

  The 2nd element will be the relevant value to work with
  """
  @type success(value) :: {:ok, value}
  @typedoc """
  A string reason for an error failure
  """
  @type reason :: String.t() | %HTTPoison.Error{} | %HTTPoison.Response{}

  @typedoc """
  An error tuple

  The 2nd element will indicate which function failed
  The 3rd element will give details of the failure
  """
  @type error(name) :: {:error, name, reason}

  @typedoc """
  A provider's documents

  * discovery_document: the provider's discovery document for OpenID Connect
  * jwk: the provider's certificates converted into a JOSE JSON Web Key
  * remaining_lifetime: how long the provider's JWK is valid for
  """
  @type documents :: %{
          discovery_document: map,
          jwk: JOSE.JWK.t(),
          remaining_lifetime: integer | nil
        }

  @spec authorization_uri(provider, params, name) :: uri
  @doc """
  Builds the authorization URI according to the spec in the providers discovery document

  The `params` option can be used to add additional query params to the URI

  Example:
      OpenIDConnect.authorization_uri(:google, %{"hd" => "dockyard.com"})

  > It is *highly suggested* that you add the `state` param for security reasons. Your
  > OpenID Connect provider should have more information on this topic.
  """
  def authorization_uri(provider, params \\ %{}, name \\ :openid_connect) do
    document = discovery_document(provider, name)
    config = config(provider, name)

    uri = Map.get(document, "authorization_endpoint")

    params =
      Map.merge(params, %{
        client_id: client_id(config),
        redirect_uri: redirect_uri(config),
        response_type: response_type(config),
        scope: normalize_scope(provider, config[:scope])
      })

    build_uri(uri, params)
  end

  @spec fetch_tokens(provider, code, name) :: success(map) | error(:fetch_tokens)
  @doc """
  Fetches the authentication tokens from the provider

  The `code` paramater should be taken from the query param `code` in the redirect
  back to your application from the provider
  """
  def fetch_tokens(provider, code, name \\ :openid_connect) do
    uri = access_token_uri(provider, name)
    config = config(provider, name)

    form_body = [
      client_id: client_id(config),
      client_secret: client_secret(config),
      code: code,
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

  @spec verify(provider, jwt, name) :: success(claims) | error(:verify)
  @doc """
  Verifies the validity of the JSON Web Token (JWT)

  This verification will assert the token's encryption against the provider's
  JSON Web Key (JWK)
  """
  def verify(provider, jwt, name \\ :openid_connect) do
    jwk = jwk(provider, name)

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

  @spec update_documents(list) :: success(documents) | error(:update_documents)
  @doc """
  Requests updated documents from the provider

  This function is used by `OpenIDConnect.Worker` for document updates
  according to the lifetime returned by the provider
  """
  def update_documents(config) do
    uri = discovery_document_uri(config)

    with {:ok, discovery_document, _} <- fetch_resource(uri),
         {:ok, certs, remaining_lifetime} <- fetch_resource(discovery_document["jwks_uri"]),
         {:ok, jwk} <- from_certs(certs) do
      {:ok,
       %{
         discovery_document: discovery_document,
         jwk: jwk,
         remaining_lifetime: remaining_lifetime
       }}
    else
      {:error, reason} -> {:error, :update_documents, reason}
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

  defp from_certs(certs) do
    try do
      {:ok, JOSE.JWK.from(certs)}
    rescue
      _ ->
        {:error, "certificates bad format"}
    end
  end

  defp discovery_document(provider, name) do
    GenServer.call(name, {:discovery_document, provider})
  end

  defp jwk(provider, name) do
    GenServer.call(name, {:jwk, provider})
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

  defp response_type(config) do
    Keyword.get(config, :response_type, "code")
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
