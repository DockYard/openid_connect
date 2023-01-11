defmodule OpenIDConnect do
  @moduledoc """
  Handles a majority of the life-cycle concerns with [OpenID Connect](http://openid.net/connect/)
  """
  alias OpenIDConnect.Document

  @typedoc """
  URL to a [OpenID Discovery Document](https://openid.net/specs/openid-connect-discovery-1_0.html) endpoint.
  """
  @type discovery_document_uri :: String.t()

  @typedoc """
  OAuth 2.0 Client Identifier valid at the Authorization Server.
  """
  @type client_id :: String.t()

  @typedoc """
  OAuth 2.0 Client Secret valid at the Authorization Server.
  """
  @type client_secret :: String.t()

  @typedoc """
  Redirection URI to which the response will be sent.

  This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider,
  with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).

  When using this flow, the Redirection URI SHOULD use the https scheme; however, it MAY use the http scheme,
  provided that the Client Type is confidential, as defined in Section 2.1 of OAuth 2.0,
  and provided the OP allows the use of http Redirection URIs in this case. The Redirection URI MAY use an alternate scheme,
  such as one that is intended to identify a callback into a native application.
  """
  @type redirect_uri :: String.t()

  @typedoc """
  OAuth 2.0 Response Type value that determines the authorization processing flow to be used,
  including what parameters are returned from the endpoints used.
  """
  @type response_type :: [String.t()] | String.t()

  @typedoc """
  OAuth 2.0 Scope Values that the Client is declaring that it will restrict itself to using.
  """
  @type scope :: [String.t()] | String.t()

  @typedoc """
  The configuration of a OpenID provider.
  """
  @type config :: %{
          required(:discovery_document_uri) => discovery_document_uri(),
          required(:client_id) => client_id(),
          required(:client_secret) => client_secret(),
          required(:redirect_uri) => redirect_uri(),
          required(:response_type) => response_type(),
          required(:scope) => scope()
        }

  @typedoc """
  JSON Web Token

  See: https://jwt.io/introduction/
  """
  @type jwt :: String.t()

  @doc """
  Builds the authorization URI according to the spec in the providers discovery document

  The `params` option can be used to add additional query params to the URI

  Example:
      OpenIDConnect.authorization_uri(:google, %{"hd" => "dockyard.com"})

  > It is *highly suggested* that you add the `state` param for security reasons. Your
  > OpenID Connect provider should have more information on this topic.
  """
  @spec authorization_uri(config(), params :: %{optional(atom) => term()}) ::
          {:ok, uri :: String.t()} | {:error, term()}
  def authorization_uri(config, params \\ %{}) do
    discovery_document_uri = config.discovery_document_uri

    with {:ok, document} <- Document.fetch_document(discovery_document_uri),
         {:ok, response_type} <- fetch_response_type(config, document),
         {:ok, scope} <- fetch_scope(config) do
      params =
        Map.merge(
          %{
            client_id: config.client_id,
            redirect_uri: config.redirect_uri,
            response_type: response_type,
            scope: scope
          },
          params
        )

      {:ok, build_uri(document.authorization_endpoint, params)}
    end
  end

  defp fetch_scope(%{scope: scope}) when is_nil(scope) or scope == [] or scope == "",
    do: {:error, :invalid_scope}

  defp fetch_scope(%{scope: scope}) when is_binary(scope),
    do: {:ok, scope}

  defp fetch_scope(%{scope: scopes}) when is_list(scopes),
    do: {:ok, Enum.join(scopes, " ")}

  defp fetch_response_type(
         %{response_type: response_type},
         %Document{response_types_supported: response_types_supported}
       ) do
    with {:ok, response_type} <- parse_response_type(response_type) do
      response_type = Enum.sort(response_type)

      if Enum.all?(response_type, &(&1 in response_types_supported)) do
        {:ok, Enum.join(response_type, " ")}
      else
        {:error,
         {:response_type_not_supported, response_types_supported: response_types_supported}}
      end
    end
  end

  defp parse_response_type(nil), do: {:error, :invalid_response_type}
  defp parse_response_type([]), do: {:error, :invalid_response_type}
  defp parse_response_type(""), do: {:error, :invalid_response_type}

  defp parse_response_type(response_type) when is_binary(response_type),
    do: {:ok, String.split(response_type)}

  defp parse_response_type(response_type) when is_list(response_type),
    do: {:ok, response_type}

  @doc """
  Builds the end session URI according to the spec in the providers discovery document

  The `params` option can be used to add additional query params to the URI

  Example:
    OpenIDConnect.end_session_uri(:azure, %{"client_id" => "5d4c39b4-660f-41c9-9a99-2a6a9c263f07"})

  See more about this feature of the OpenID Connect spec:
    https://openid.net/specs/openid-connect-rpinitiated-1_0.html

  Each provider will typically require one or more of the supported query params, e.g. `id_token_hint` or
  `client_id`. Read your provider's OIDC documentation to determine which one(s) you should add.

  Some providers don't specify `end_session_endpoint` in their discovery documents,
  in such cases `{:error, :endpoint_not_set}` is returned.
  """
  @spec end_session_uri(config(), params :: %{optional(atom) => term()}) ::
          {:ok, uri :: String.t()} | {:error, term()}
  def end_session_uri(config, params \\ %{}) do
    discovery_document_uri = config.discovery_document_uri

    with {:ok, document} <- Document.fetch_document(discovery_document_uri) do
      if end_session_endpoint = document.end_session_endpoint do
        params = Map.merge(%{client_id: config.client_id}, params)
        {:ok, build_uri(end_session_endpoint, params)}
      else
        {:error, :endpoint_not_set}
      end
    end
  end

  @doc """
  Fetches the authentication tokens from the provider

  The `params` option should at least include the key/value pairs of the `response_type` that
  was requested during authorization. `params` may also include any one-off overrides for token
  fetching.
  """
  @spec fetch_tokens(config(), params :: %{optional(atom) => term()}) ::
          {:ok, response :: map()} | {:error, term()}
  def fetch_tokens(config, params) do
    discovery_document_uri = config.discovery_document_uri

    form_body =
      Map.merge(
        %{
          client_id: config.client_id,
          client_secret: config.client_secret,
          redirect_uri: config.redirect_uri,
          grant_type: "authorization_code"
        },
        params
      )
      |> URI.encode_query(:www_form)

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    with {:ok, document} <- Document.fetch_document(discovery_document_uri),
         request = Finch.build(:post, document.token_endpoint, headers, form_body),
         {:ok, %Finch.Response{body: response, status: status}} when status in 200..299 <-
           Finch.request(request, OpenIDConnect.Finch),
         {:ok, json} <- Jason.decode(response) do
      {:ok, json}
    else
      {:ok, %Finch.Response{body: response, status: status}} -> {:error, {status, response}}
      other -> other
    end
  end

  @doc """
  Verifies the validity of the JSON Web Token (JWT)

  This verification will assert the token's encryption against the provider's
  JSON Web Key (JWK)
  """
  @spec verify(config(), jwt :: String.t()) ::
          {:ok, claims :: map()} | {:error, term()}
  def verify(config, jwt) do
    discovery_document_uri = config.discovery_document_uri

    with {:ok, protected} <- peek_protected(jwt),
         {:ok, decoded_protected} <- Jason.decode(protected),
         {:ok, token_alg} <- Map.fetch(decoded_protected, "alg"),
         {:ok, document} <- Document.fetch_document(discovery_document_uri),
         {true, claims, _jwk} <- do_verify(document.jwks, token_alg, jwt) do
      Jason.decode(claims)
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, {:invalid_jwt, "token claims did not contain a JSON payload"}}

      {:error, :peek_protected} ->
        {:error, {:invalid_jwt, "invalid token format"}}

      :error ->
        {:error, {:invalid_jwt, "no `alg` found in token"}}

      {false, _claims, _jwk} ->
        {:error, {:invalid_jwt, "verification failed"}}

      {:error, {:case_clause, _}} ->
        {:error, {:invalid_jwt, "verification failed"}}

      other ->
        other
    end
  end

  defp peek_protected(jwks) do
    {:ok, JOSE.JWS.peek_protected(jwks)}
  rescue
    _ -> {:error, :peek_protected}
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

  defp build_uri(uri, params) do
    query = URI.encode_query(params)

    uri
    |> URI.merge("?#{query}")
    |> URI.to_string()
  end
end
