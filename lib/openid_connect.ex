defmodule OpenIDConnect do
  @moduledoc """
  OpenID Connect client library for Elixir.

  This library provides a complete implementation of the [OpenID Connect](https://openid.net/connect/) 
  authentication protocol, which is built on top of OAuth 2.0. It handles the complete authentication 
  flow including:

  * Generating authorization URIs for redirecting users to identity providers
  * Fetching tokens from the token endpoint
  * Verifying JWT ID tokens using provider JWKs (JSON Web Keys)
  * Fetching user information from the userinfo endpoint
  * Supporting provider logout via end session endpoints

  ## Supported Authentication Flows

  The library supports the standard OpenID Connect authentication flows:

  * Authorization Code Flow (most common for web applications)
  * Implicit Flow (less secure, used for JavaScript applications)
  * Hybrid Flow (combines aspects of both)

  ## Supported Identity Providers

  This library works with any OpenID Connect compliant provider, including:

  * Google
  * Microsoft Azure AD
  * Auth0
  * Okta
  * Amazon Cognito
  * Keycloak
  * OneLogin
  * HashiCorp Vault
  * And many others

  ## Basic Usage

  ```elixir
  # Step 1: Configure the provider
  google_config = %{
    discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
    client_id: "YOUR_CLIENT_ID",
    client_secret: "YOUR_CLIENT_SECRET",
    response_type: "code",
    scope: "openid email profile"
  }

  # Step 2: Generate the authorization URI (redirect the user to this URI)
  {:ok, uri} = OpenIDConnect.authorization_uri(
    google_config,
    "https://example.com/auth/callback",
    %{state: state_token}
  )

  # Step 3: Exchange the authorization code for tokens
  {:ok, tokens} = OpenIDConnect.fetch_tokens(
    google_config,
    %{
      code: auth_code,
      redirect_uri: "https://example.com/auth/callback"
    }
  )

  # Step 4: Verify the ID token
  {:ok, claims} = OpenIDConnect.verify(google_config, tokens["id_token"])

  # Optional: Fetch additional user information
  {:ok, userinfo} = OpenIDConnect.fetch_userinfo(google_config, tokens["access_token"])
  ```

  See the [README](readme.html) for more detailed examples and configuration options.
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
          required(:response_type) => response_type(),
          required(:scope) => scope(),
          optional(:leeway) => non_neg_integer()
        }

  @typedoc """
  JSON Web Token

  See: https://jwt.io/introduction/
  """
  @type jwt :: String.t()

  @doc """
  Builds an authorization URI for redirecting users to the identity provider.

  This function creates a URL that starts the OpenID Connect authentication flow
  by redirecting the user to the provider's authorization endpoint. The endpoint URL
  is automatically retrieved from the provider's discovery document.

  ## Parameters

  * `config` - The provider configuration map
  * `redirect_uri` - URI to redirect to after authentication (must match one registered with the provider)
  * `params` - Optional map of additional query parameters to include in the authorization URI

  ## Common Additional Parameters

  * `state` - **Strongly recommended** - Random token to prevent CSRF attacks
  * `prompt` - Controls the login experience, common values include:
    * `"none"` - No interactive prompt, fails if user authentication is required
    * `"login"` - Forces the user to enter their credentials even if already logged in
    * `"consent"` - Forces the consent screen to be displayed even if previously consented
    * `"select_account"` - Prompts the user to select an account
  * `login_hint` - Email address or sub identifier to pre-fill the login form
  * `max_age` - Maximum elapsed time in seconds since last authentication
  * `ui_locales` - Preferred languages for the UI, space-separated list of BCP47 tags
  * `acr_values` - Authentication Context Class Reference values

  ## Provider-Specific Parameters

  Some providers support additional custom parameters:

  * Google: `hd` (hosted domain) to restrict to specific Google Workspace domains
  * Azure AD: `domain_hint` to skip the home realm discovery page
  * Many others based on the provider

  ## Returns

  * `{:ok, uri}` - On success, returns the authorization URI string
  * `{:error, reason}` - On failure, returns an error tuple with details

  ## Example: Basic Usage

  ```elixir
  {:ok, uri} = OpenIDConnect.authorization_uri(
    google_config,
    "https://example.com/auth/callback",
    %{state: state_token}
  )
  ```

  ## Example: With Additional Parameters

  ```elixir
  {:ok, uri} = OpenIDConnect.authorization_uri(
    google_config,
    "https://example.com/auth/callback",
    %{
      state: state_token,
      prompt: "login",
      login_hint: "user@example.com",
      hd: "example.com"  # Google-specific parameter
    }
  )
  ```

  ## Security: State Parameter

  The `state` parameter is critical for preventing cross-site request forgery attacks.
  Always include a state parameter with a secure random value and validate it when
  the user is redirected back to your application.

  ### Creating a State Token

  ```elixir
  state_token = Base.encode64(:crypto.strong_rand_bytes(32), padding: false)

  # Store the token in your session
  conn = Plug.Conn.put_session(conn, :oidc_state_token, state_token)

  # Include it in the authorization URI
  {:ok, uri} = OpenIDConnect.authorization_uri(
    google_config,
    redirect_uri,
    %{state: state_token}
  )
  ```

  ### Validating the State Token

  When the provider redirects back to your application, verify the state parameter:

  ```elixir
  stored_token = Plug.Conn.get_session(conn, :oidc_state_token)
  received_token = params["state"]

  if stored_token && Plug.Crypto.secure_compare(stored_token, received_token) do
    # State token is valid, proceed with token exchange
  else
    # Invalid state token, reject the request
  end
  ```

  For more details on state tokens, see [Google's Documentation](https://developers.google.com/identity/openid-connect/openid-connect#createxsrftoken).
  """
  @spec authorization_uri(
          config(),
          redirect_uri :: redirect_uri(),
          params :: %{optional(atom) => term()}
        ) :: {:ok, uri :: String.t()} | {:error, term()}
  def authorization_uri(config, redirect_uri, params \\ %{}) do
    discovery_document_uri = config.discovery_document_uri

    with {:ok, document} <- Document.fetch_document(discovery_document_uri),
         {:ok, response_type} <- fetch_response_type(config, document),
         {:ok, scope} <- fetch_scope(config) do
      params =
        Map.merge(
          %{
            client_id: config.client_id,
            redirect_uri: redirect_uri,
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
  Builds a URI for ending the user's session with the identity provider.

  This function creates a URL for OpenID Connect RP-Initiated Logout, allowing
  your application to sign the user out of the identity provider's session.
  The endpoint URL is automatically retrieved from the provider's discovery document.

  ## Parameters

  * `config` - The provider configuration map
  * `params` - Optional map of additional query parameters for the end session URI

  ## Common Additional Parameters

  * `id_token_hint` - The ID token previously issued to the user (strongly recommended)
  * `post_logout_redirect_uri` - URI to redirect to after logout (must be registered with provider)
  * `state` - Opaque value for maintaining state between logout request and callback

  ## Provider Requirements

  Different providers have different requirements for logout:

  * Azure AD: Requires `post_logout_redirect_uri` and may accept `id_token_hint`
  * Auth0: Requires `client_id` and `returnTo` (instead of `post_logout_redirect_uri`)
  * Cognito: Requires `client_id` and `logout_uri` (their name for redirect URI)
  * Okta: Requires `id_token_hint` and accepts `post_logout_redirect_uri`
  * Keycloak: Accepts `id_token_hint` and `post_logout_redirect_uri`

  Always consult your provider's documentation for specific requirements.

  ## Returns

  * `{:ok, uri}` - On success, returns the end session URI string
  * `{:error, :endpoint_not_set}` - If the provider doesn't support RP-Initiated Logout
  * `{:error, reason}` - On other failures, returns an error tuple with details

  ## Provider Support Note

  Not all providers support RP-Initiated Logout. If the provider's discovery document
  doesn't include an `end_session_endpoint`, this function will return
  `{:error, :endpoint_not_set}`. In such cases, you'll need to implement session
  termination in your application only.

  ## Example: Azure AD Logout

  ```elixir
  {:ok, logout_uri} = OpenIDConnect.end_session_uri(
    azure_config,
    %{
      post_logout_redirect_uri: "https://example.com/logged-out"
    }
  )

  # Redirect the user to the logout_uri
  redirect(conn, external: logout_uri)
  ```

  ## Example: With ID Token Hint

  ```elixir
  {:ok, logout_uri} = OpenIDConnect.end_session_uri(
    okta_config,
    %{
      id_token_hint: id_token,
      post_logout_redirect_uri: "https://example.com/logged-out"
    }
  )
  ```

  For more details, see the [OpenID Connect RP-Initiated Logout Specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
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
  Fetches authentication tokens from the provider using the token endpoint.

  This function exchanges the authorization code or refresh token for access and ID tokens
  from the identity provider's token endpoint. The endpoint URL is automatically retrieved
  from the provider's discovery document.

  ## Parameters

  * `config` - The provider configuration map
  * `params` - A map of parameters to send to the token endpoint

  ## Common Parameters

  The params map should include different fields depending on the grant type:

  ### Authorization Code Grant (most common)

  ```elixir
  %{
    code: "AUTHORIZATION_CODE_FROM_CALLBACK",
    redirect_uri: "https://example.com/callback", # Must match the original redirect_uri
    grant_type: "authorization_code" # Optional, defaults to "authorization_code"
  }
  ```

  ### Refresh Token Grant

  ```elixir
  %{
    refresh_token: "REFRESH_TOKEN",
    grant_type: "refresh_token"
  }
  ```

  ## Returns

  * `{:ok, tokens}` - On successful token exchange, returns a map containing at minimum:
    * `"access_token"` - The OAuth 2.0 access token
    * `"token_type"` - The token type (typically "Bearer")
    * `"expires_in"` - Token lifetime in seconds
    * `"id_token"` - The OpenID Connect ID token (JWT)
    * `"refresh_token"` - Optional refresh token for obtaining new access tokens

  * `{:error, reason}` - On failure, returns an error tuple with reason

  ## Example

  ```elixir
  {:ok, tokens} = OpenIDConnect.fetch_tokens(
    google_config,
    %{
      code: params["code"],
      redirect_uri: "https://example.com/auth/callback" 
    }
  )

  # Access the tokens
  access_token = tokens["access_token"]
  id_token = tokens["id_token"]
  refresh_token = tokens["refresh_token"]
  ```

  For more details, see the [OpenID Connect spec](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint).
  """
  @spec fetch_tokens(config(), params :: %{optional(atom) => term()}) ::
          {:ok, response :: map()} | {:error, term()}
  def fetch_tokens(config, params) do
    discovery_document_uri = config.discovery_document_uri

    form_body =
      %{client_id: config.client_id, client_secret: config.client_secret}
      |> Map.merge(params)
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
  Verifies the validity and authenticity of an OpenID Connect ID token.

  This security-critical function verifies that:

  1. The token's signature is valid and was signed by the provider's key
  2. The token has not expired (checking the "exp" claim)
  3. The token is intended for your application (checking the "aud" claim)

  ## Parameters

  * `config` - The provider configuration map
  * `jwt` - The ID token string (a JSON Web Token) from the tokens response

  ## Returns

  * `{:ok, claims}` - On successful verification, returns the decoded claims from the token
  * `{:error, reason}` - On verification failure, returns an error tuple with details

  ## Verification Process

  1. The signature is verified using the provider's JSON Web Keys (JWKs), which are fetched
     from the provider's JWKs endpoint listed in the discovery document.
  2. The "exp" (expiration) claim is checked to ensure the token has not expired.
     A configurable leeway (default: 30 seconds) is allowed to account for clock skew.
  3. The "aud" (audience) claim is verified to ensure the token is intended for your
     application, as identified by your client_id.

  ## Example

  ```elixir
  {:ok, claims} = OpenIDConnect.verify(google_config, id_token)

  # Common claims you might find in the response:
  user_id = claims["sub"]         # Unique user identifier
  email = claims["email"]         # User's email (if in scope)
  name = claims["name"]           # User's name (if in scope)
  picture = claims["picture"]     # URL to user's profile picture (if available)
  issuer = claims["iss"]          # Identifies the token issuer
  ```

  ## Security Warning

  Always verify tokens before trusting their contents. Never use token data for
  authentication purposes without verification, as tokens could be forged or tampered with.
  """
  @spec verify(config(), jwt :: String.t()) ::
          {:ok, claims :: map()} | {:error, term()}
  def verify(config, jwt) do
    discovery_document_uri = config.discovery_document_uri

    with {:ok, protected} <- peek_protected(jwt),
         {:ok, decoded_protected} <- Jason.decode(protected),
         {:ok, token_alg} <- Map.fetch(decoded_protected, "alg"),
         {:ok, document} <- Document.fetch_document(discovery_document_uri),
         {true, claims, _jwk} <- verify_signature(document.jwks, token_alg, jwt),
         {:ok, unverified_claims} <- Jason.decode(claims),
         {:ok, verified_claims} <- verify_claims(unverified_claims, config) do
      {:ok, verified_claims}
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, {:invalid_jwt, "token claims did not contain a JSON payload"}}

      {:error, :peek_protected} ->
        {:error, {:invalid_jwt, "invalid token format"}}

      {:error, invalid_claim, message} ->
        {:error, {:invalid_jwt, "invalid #{invalid_claim} claim: #{message}"}}

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

  defp verify_signature(%JOSE.JWK{keys: {:jose_jwk_set, jwks}}, token_alg, jwt) do
    Enum.find_value(jwks, {false, "{}", jwt}, fn jwk ->
      jwk
      |> JOSE.JWK.from()
      |> verify_signature(token_alg, jwt)
      |> case do
        {false, _claims, _jwt} -> false
        verified_claims -> verified_claims
      end
    end)
  end

  defp verify_signature(%JOSE.JWK{} = jwk, token_alg, jwt),
    do: JOSE.JWS.verify_strict(jwk, [token_alg], jwt)

  defp verify_claims(claims, config) do
    leeway = Map.get(config, :leeway, 30)
    client_id = Map.fetch!(config, :client_id)

    with :ok <- verify_exp_claim(claims, leeway),
         :ok <- verify_aud_claim(claims, client_id) do
      {:ok, claims}
    end
  end

  defp verify_exp_claim(claims, leeway) do
    case Map.fetch(claims, "exp") do
      {:ok, exp} when is_integer(exp) ->
        epoch = DateTime.utc_now() |> DateTime.to_unix()

        if epoch < exp + leeway,
          do: :ok,
          else: {:error, "exp", "token has expired"}

      {:ok, _exp} ->
        {:error, "exp", "is invalid"}

      :error ->
        {:error, "exp", "missing"}
    end
  end

  defp verify_aud_claim(claims, expected_aud) do
    case Map.fetch(claims, "aud") do
      {:ok, aud} ->
        if audience_matches?(aud, expected_aud),
          do: :ok,
          else: {:error, "aud", "token is intended for another application"}

      :error ->
        {:error, "aud", "missing"}
    end
  end

  defp audience_matches?(aud, expected_aud) when is_list(aud), do: Enum.member?(aud, expected_aud)
  defp audience_matches?(aud, expected_aud), do: aud === expected_aud

  @doc """
  Fetches information about the authenticated user from the userinfo endpoint.

  This function retrieves additional claims about the end-user from the provider's
  userinfo endpoint using the access token. This can be useful when you need user
  attributes that weren't included in the ID token claims.

  ## Parameters

  * `config` - The provider configuration map
  * `access_token` - The OAuth 2.0 access token obtained from `fetch_tokens/2`

  ## Returns

  * `{:ok, userinfo}` - On success, returns a map of user information
  * `{:error, reason}` - On failure, returns an error tuple with details

  ## Userinfo Claims

  The returned claims will depend on the scopes requested during authorization,
  but typically include:

  * `"sub"` - Subject identifier (unique user ID)
  * `"name"` - User's full name (if "profile" scope)
  * `"given_name"` - First name (if "profile" scope)
  * `"family_name"` - Last name (if "profile" scope)
  * `"email"` - Email address (if "email" scope)
  * `"email_verified"` - Boolean indicating if email is verified (if "email" scope)
  * `"picture"` - URL to profile picture (if "profile" scope)

  ## Example

  ```elixir
  {:ok, userinfo} = OpenIDConnect.fetch_userinfo(google_config, access_token)

  # Access user information
  user_id = userinfo["sub"]
  email = userinfo["email"]
  name = userinfo["name"]
  ```

  ## Security Note

  The userinfo endpoint requires a valid access token. The token must have
  appropriate scopes (typically "openid" and others like "profile" or "email").

  For more details, see the [OpenID Connect UserInfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
  """
  @spec fetch_userinfo(config(), jwt()) :: {:ok, response :: map()} | {:error, term()}
  def fetch_userinfo(config, access_token) do
    discovery_document_uri = config.discovery_document_uri

    headers = [{"Authorization", "Bearer #{access_token}"}]

    with {:ok, document} <- Document.fetch_document(discovery_document_uri),
         request = Finch.build(:get, document.userinfo_endpoint, headers),
         {:ok, %Finch.Response{body: response, status: status}} when status in 200..299 <-
           Finch.request(request, OpenIDConnect.Finch),
         {:ok, json} <- Jason.decode(response) do
      {:ok, json}
    else
      {:ok, %Finch.Response{body: response, status: status}} -> {:error, {status, response}}
      other -> other
    end
  end

  defp build_uri(uri, params) do
    query = URI.encode_query(params)

    uri
    |> URI.merge("?#{query}")
    |> URI.to_string()
  end
end
