# Complete Phoenix Example

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



