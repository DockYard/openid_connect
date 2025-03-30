# OpenIDConnect

Client library for consuming and working with OpenID Connect Providers

**[OpenIDConnect is built and maintained by DockYard, contact us for expert Elixir and Phoenix consulting](https://dockyard.com/phoenix-consulting)**.

## Installation

[Available in Hex](https://hex.pm/packages/openid_connect), the package can be installed as:

Add `openid_connect` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:openid_connect, "~> 1.0.0"}]
end
```

## Getting Started

### Configuration

This library works with any OpenID Connect provider through a standard configuration map. You'll need to create a configuration map for each provider you want to work with:

```elixir
google_config = %{
  discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
  client_id: "CLIENT_ID",
  client_secret: "CLIENT_SECRET",
  redirect_uri: "https://example.com/session",
  response_type: "code",
  scope: "openid email profile"
}
```

The configuration requires:
- `discovery_document_uri`: URL to the OpenID Connect Discovery Document
- `client_id`: OAuth 2.0 Client Identifier provided by your identity provider
- `client_secret`: OAuth 2.0 Client Secret provided by your identity provider
- `response_type`: OAuth 2.0 Response Type (typically "code" for authorization code flow)
- `scope`: Space-separated list of scopes (must include "openid")

Additional optional configuration:
- `leeway`: Number of seconds to allow for clock skew when verifying token expiration (default: 30)

Most major OAuth2 providers support OpenID Connect, including:
- Google
- Microsoft Azure AD
- Auth0
- Okta
- AWS Cognito
- Keycloak
- OneLogin
- Many others

For a full list, see [major OpenID Connect providers](https://en.wikipedia.org/wiki/List_of_OAuth_providers).

### Usage

Implementing OpenID Connect authentication in your app involves these steps:

1. Generate an authorization URI and redirect the user to it
2. Handle the callback from the provider after successful authentication
3. Exchange the authorization code for tokens
4. Verify the ID token
5. Use the claims to establish a user session

#### 1. Generate the Authorization URI

Create a URL that will redirect the user to the provider's login page:

```elixir
{:ok, uri} = OpenIDConnect.authorization_uri(
  google_config,
  "https://example.com/auth/callback",
  %{state: state_token}
)
```

You should:
- Generate a secure state token for CSRF protection
- Store this state token in your session
- Include the state token in the authorization URI

#### 2. Handle the Callback from the Provider

After the user logs in, the provider redirects back to your `redirect_uri` with an authorization code and the state token you provided:

```elixir
# In your callback controller/handler
def callback(conn, params) do
  # First verify that the state parameter matches the one we stored
  stored_state = get_session(conn, :state_token)
  received_state = params["state"]
  
  if Plug.Crypto.secure_compare(stored_state, received_state) do
    # State is valid, proceed with code exchange
    handle_valid_callback(conn, params)
  else
    # State token doesn't match, reject the request
    conn
    |> put_status(401)
    |> render("error.html", error: "Invalid state parameter")
  end
end
```

#### 3. Exchange the Authorization Code for Tokens

Exchange the code for ID and access tokens:

```elixir
{:ok, tokens} = OpenIDConnect.fetch_tokens(google_config, %{
  code: params["code"],
  redirect_uri: "https://example.com/auth/callback"  # Must match original redirect_uri
})

# tokens will contain:
# %{
#   "access_token" => "ya29.a0AfB_...",
#   "id_token" => "eyJhbGciOiJSUzI1...",
#   "expires_in" => 3599,
#   "token_type" => "Bearer",
#   "refresh_token" => "1//03s..." (if requested)
# }
```

#### 4. Verify the ID Token

The ID token is a JWT containing claims about the user. Always verify it before trusting its contents:

```elixir
{:ok, claims} = OpenIDConnect.verify(google_config, tokens["id_token"])

# claims will contain user information like:
# %{
#   "sub" => "10865933565....",  # Unique user identifier
#   "email" => "user@example.com",
#   "email_verified" => true,
#   "name" => "User Name",
#   "picture" => "https://...",
#   "given_name" => "User",
#   "family_name" => "Name",
#   "locale" => "en",
#   "iat" => 1585662674,  # Issued at timestamp
#   "exp" => 1585666274,  # Expiration timestamp
#   "aud" => "YOUR_CLIENT_ID",
#   "iss" => "https://accounts.google.com"
# }
```

#### 5. Use the Claims to Establish a User Session

Use the verified claims to identify your user and establish a session:

```elixir
# The "sub" claim is the unique identifier for the user
user_id = claims["sub"]

# Find or create a user in your system
user = find_or_create_user(user_id, claims)

# Establish a session for this user
conn
|> put_session(:user_id, user.id)
|> redirect(to: "/dashboard")
```

#### Optional: Fetch Additional User Information

Some providers allow you to fetch additional user information using the access token:

```elixir
{:ok, userinfo} = OpenIDConnect.fetch_userinfo(google_config, tokens["access_token"])
```

#### Ending a User Session

Some providers support log out via an end session endpoint:

```elixir
{:ok, logout_uri} = OpenIDConnect.end_session_uri(
  google_config,
  %{id_token_hint: id_token, post_logout_redirect_uri: "https://example.com/logout/callback"}
)

# Redirect the user to the logout_uri
redirect(conn, external: logout_uri)
```

### Complete Phoenix Example

Here's a complete example of implementing OpenID Connect authentication in a Phoenix application:

```elixir
# Configuration in config/config.exs
config :my_app, :google_oidc_config, %{
  discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
  client_id: System.get_env("GOOGLE_CLIENT_ID"),
  client_secret: System.get_env("GOOGLE_CLIENT_SECRET"),
  response_type: "code",
  scope: "openid email profile"
}

# Routes in lib/my_app_web/router.ex
scope "/auth", MyAppWeb do
  pipe_through [:browser, :redirect_if_authenticated]
  
  get "/google", AuthController, :request
  get "/google/callback", AuthController, :callback
  get "/logout", AuthController, :logout
end

# Controller in lib/my_app_web/controllers/auth_controller.ex
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller
  
  @doc """
  Initiates the OpenID Connect authentication flow
  """
  def request(conn, _params) do
    google_config = Application.fetch_env!(:my_app, :google_oidc_config)
    
    # Generate a secure state token to prevent CSRF
    state_token = Base.encode64(:crypto.strong_rand_bytes(32), padding: false)
    
    # The redirect_uri must match what your provider has configured
    redirect_uri = Routes.auth_url(conn, :callback)
    
    {:ok, auth_uri} = OpenIDConnect.authorization_uri(
      google_config,
      redirect_uri,
      %{state: state_token}
    )
    
    conn
    |> put_session(:oidc_state_token, state_token)
    |> redirect(external: auth_uri)
  end
  
  @doc """
  Handles the callback from the OpenID provider after successful authentication
  """
  def callback(conn, params) do
    google_config = Application.fetch_env!(:my_app, :google_oidc_config)
    
    # Verify the state parameter to prevent CSRF attacks
    with true <- valid_state_token?(conn, params["state"]),
         {:ok, tokens} <- OpenIDConnect.fetch_tokens(
           google_config,
           %{
             code: params["code"],
             redirect_uri: Routes.auth_url(conn, :callback)
           }
         ),
         {:ok, claims} <- OpenIDConnect.verify(google_config, tokens["id_token"]) do
      
      # Store tokens securely, typically in the session or a secure cookie
      # Storing in the session should be fine for most cases
      conn = put_session(conn, :access_token, tokens["access_token"])
      
      # Find or create the user based on the claims
      user = 
        case Accounts.get_user_by_provider_id("google", claims["sub"]) do
          nil -> 
            {:ok, user} = Accounts.create_user(%{
              email: claims["email"],
              name: claims["name"],
              provider: "google",
              provider_id: claims["sub"]
            })
            user
          user -> 
            user
        end
      
      # Establish the user's session
      conn
      |> put_session(:current_user_id, user.id)
      |> configure_session(renew: true)
      |> put_flash(:info, "Successfully signed in!")
      |> redirect(to: Routes.dashboard_path(conn, :index))
    else
      false -> 
        # Invalid state token, potential CSRF attack
        conn
        |> put_flash(:error, "Authentication failed: Invalid state parameter")
        |> redirect(to: Routes.page_path(conn, :index))
      
      {:error, reason} ->
        # Log the error for debugging
        require Logger
        Logger.error("Authentication error: #{inspect(reason)}")
        
        conn
        |> put_flash(:error, "Authentication failed")
        |> redirect(to: Routes.page_path(conn, :index))
    end
  end
  
  @doc """
  Logs the user out by clearing the session
  """
  def logout(conn, _params) do
    google_config = Application.fetch_env!(:my_app, :google_oidc_config)
    id_token = get_session(conn, :id_token)
    
    # Clear our local session
    conn = 
      conn
      |> configure_session(drop: true)
      |> put_flash(:info, "Successfully signed out!")
    
    # If we have an ID token, try to use the provider's logout endpoint
    if id_token do
      case OpenIDConnect.end_session_uri(
        google_config,
        %{
          id_token_hint: id_token,
          post_logout_redirect_uri: Routes.page_url(conn, :index)
        }
      ) do
        {:ok, logout_uri} ->
          redirect(conn, external: logout_uri)
        _ ->
          # Fall back to local logout if provider doesn't support end_session
          redirect(conn, to: Routes.page_path(conn, :index))
      end
    else
      redirect(conn, to: Routes.page_path(conn, :index))
    end
  end
  
  # Verify the state token to prevent CSRF attacks
  defp valid_state_token?(conn, token) do
    stored_token = get_session(conn, :oidc_state_token)
    
    # Clear the token to prevent replay attacks
    conn = delete_session(conn, :oidc_state_token)
    
    case stored_token do
      nil -> false
      ^token -> true
      _ -> false
    end
  end
end
```

**Key Security Considerations:**

1. Always validate the state token
2. Store secrets (client ID, client secret) in environment variables
3. Verify the ID token before trusting its contents
4. Use HTTPS for all redirect URIs
5. Consider token storage carefully - sessions are usually appropriate
6. Clear tokens when logging out

## Authors

- [Brian Cardarella](http://twitter.com/bcardarella)

[We are very thankful for the many contributors](https://github.com/dockyard/openid_connect/graphs/contributors)

## Versioning

This library follows [Semantic Versioning](http://semver.org)

## Looking for help with your Elixir project?

[At DockYard we are ready to help you build your next Elixir project](https://dockyard.com/phoenix-consulting). We have a unique expertise in Elixir and Phoenix development that is unmatched. [Get in touch!](https://dockyard.com/contact/hire-us)

At DockYard we love Elixir! You can [read our Elixir blog posts](https://dockyard.com/blog/categories/elixir)
or come visit us at [The Boston Elixir Meetup](http://www.meetup.com/Boston-Elixir/) that we organize.

## Want to help?

Please do! We are always looking to improve this library. Please see our
[Contribution Guidelines](https://github.com/dockyard/openid_connect/blob/master/CONTRIBUTING.md)
on how to properly submit issues and pull requests.

## Legal

[DockYard](http://dockyard.com/), Inc. &copy; 2018

[@dockyard](http://twitter.com/dockyard)

[Licensed under the MIT license](http://www.opensource.org/licenses/mit-license.php)
