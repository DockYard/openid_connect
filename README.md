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

Most of the functions expect a `config` map which means application developer should take care for the storage of those options, eg:

```elixir
google_config = %{
  discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
  client_id: "CLIENT_ID",
  client_secret: "CLIENT_SECRET",
  redirect_uri: "https://example.com/session",
  response_type: "code",
  scope: "openid email profile"
}

authorization_uri(google_config)
```

Most major OAuth2 providers have added support for OpenIDConnect. [See a short list of most major adopters of OpenIDConnect](https://en.wikipedia.org/wiki/List_of_OAuth_providers).

### Usage

In your app code you will need to do a few things:

1. Expose the `authorization_uri` for the provider(s)
2. Have your app handle the redirect from the provider
3. Fetch the JWT
4. Verify the JWT from the provider
5. Read the claim payload to set whatever session data your app requires

#### Exposing the authorization uri

You can build the correct authorization URI for a provider with:

```elixir
OpenIDConnect.authorization_uri(google_config)
```

In this case we are requesting that `OpenIDConnect` build the authorization URI for
the google provider. You should use this URI for your users to link out to for
authenticating with the given provider

#### Handling the redirect from the provider

You will need an endpoint for the provider to redirect to after the user has authenticated. This
is where the remainder of your steps will take place.

#### Fetch the JWT

The JSON Web Token (JWT) must be fetched, using the key/value pairs from the `response_type` params that were
part of the redirect to your application:

```elixir
{:ok, tokens} = OpenIDConnect.fetch_tokens(google_config, %{code: params["code"]})
```

#### Verify the JWT

The JWT is encrypted and it should always be verified with the JSON Web Keys (JWK) for the provider:

```elixir
{:ok, claims} = OpenIDConnect.verify(google_config, tokens["id_token"])
```

The `claims` is a payload with the information from the `scopes` you requested of the provider.

#### Read the claims and set your app's user session

Now that you have the `claims` payload you can use the user data to identify and set the user's session state for your app.
Setting your app's session state is outside the scope of this library.

### Phoenix Example

```elixir
# router.ex
get("/session", SessionController, :create)
get("/session/authorization-uri", SessionController, :authorization_uri)

# session_controller.ex
# you could also take the `provider` as a query param to pass into the function
def authorization_uri(conn, _params) do
  google_config = Application.fetch_env!(:my_app, :google_oidc_config)
  {:ok, uri} = OpenIDConnect.authorization_uri(google_config)

  json(conn, %{uri: uri})
end

# The `Authentication` module here is an imaginary interface for setting session state
def create(conn, params) do
  google_config = Application.fetch_env!(:my_app, :google_oidc_config)

  with {:ok, tokens} <- OpenIDConnect.fetch_tokens(google_config, params["code"]),
       {:ok, claims} <- OpenIDConnect.verify(google_config, tokens["id_token"]),
       {:ok, user} <- Authentication.call(google_config, Repo, claims) do

    conn
    |> put_status(200)
    |> render(UserView, "show.html", data: user)
  else
    _ -> send_resp(conn, 401, "")
  end
end
```

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
