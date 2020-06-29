# OpenIDConnect

Client library for consuming and working with OpenID Connect Providers

**[OpenIDConnect is built and maintained by DockYard, contact us for expert Elixir and Phoenix consulting](https://dockyard.com/phoenix-consulting)**.

## Installation

[Available in Hex](https://hex.pm/packages/openid_connect), the package can be installed as:

Add `openid_connect` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:openid_connect, "~> 0.2.2"}]
end
```

## Getting Started


### Configuration

You should add the configuration settings for each of your providers into one of your app's configuration:

```elixir
config :my_app, :openid_connect_providers,
  google: [
    discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",
    client_id: "CLIENT_ID",
    client_secret: "CLIENT_SECRET",
    redirect_uri: "https://example.com/session",
    response_type: "code",
    scope: "openid email profile"
  ]
```

You *must* setup with your provider first. Your provider will have the correct data to provider for the config settings above.

Most major OAuth2 providers have added support for OpenIDConnect. [See a short list of most major adopters of OpenIDConnect](https://en.wikipedia.org/wiki/List_of_OAuth_providers).

> You can add multiple providers in the list. The key for each provider is just a reference that you'll
> use with the `OpenIDConnect` module in your app code.

### Worker

Next add the `OpenIDConnect.Worker` to your app's supervisor along with your provider configs.

```elixir
children =
  [
    worker(OpenIDConnect.Worker, [Application.get_env(:my_app, :openid_connect_providers)]),
  ]

opts = [strategy: :one_for_one, name: MyApp.Supervisor]
Supervisor.start_link(children, opts)
```

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
OpenIDConnect.authorization_uri(:google)
```

In this case we are requesting that `OpenIDConnect` build the authorization URI for
the `:google` provider that we setup on in configuration above. You should use this URI for
your users to link out to for authenticating with the given provider

#### Handling the redirect from the provider

You will need an endpoint for the provider to redirect to after the user has authenticated. This
is where the remainder of your steps will take place.

#### Fetch the JWT

The JSON Web Token (JWT) must be fetched, using the key/value pairs from the `response_type` params that were
part of the redirect to your application:

```elixir
{:ok, tokens} = OpenIDConnect.fetch_tokens(:google, %{code: params["code"]})
```

#### Verify the JWT

The JWT is encrypted and it should always be verified with the JSON Web Keys (JWK) for the provider:

```elixir
{:ok, claims} = OpenIDConnect.verify(:google, tokens["id_token"])
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
  json(conn, %{uri: OpenIDConnect.authorization_uri(:google)})
end

# The `Authentication` module here is an imaginary interface for setting session state
def create(conn, params) do
  with {:ok, tokens} <- OpenIDConnect.fetch_tokens(:google, params["code"]),
       {:ok, claims} <- OpenIDConnect.verify(:google, tokens["id_token"]),
       {:ok, user} <- Authentication.call(:google, Repo, claims) do

    conn
    |> put_status(200)
    |> render(UserView, "show.html", data: user)
  else
    _ -> send_resp(conn, 401, "")
  end
end
```

## Authors ##

* [Brian Cardarella](http://twitter.com/bcardarella)

[We are very thankful for the many contributors](https://github.com/dockyard/openid_connect/graphs/contributors)

## Versioning ##

This library follows [Semantic Versioning](http://semver.org)

## Looking for help with your Elixir project? ##

[At DockYard we are ready to help you build your next Elixir project](https://dockyard.com/phoenix-consulting). We have a unique expertise in Elixir and Phoenix development that is unmatched. [Get in touch!](https://dockyard.com/contact/hire-us)

At DockYard we love Elixir! You can [read our Elixir blog posts](https://dockyard.com/blog/categories/elixir)
or come visit us at [The Boston Elixir Meetup](http://www.meetup.com/Boston-Elixir/) that we organize.

## Want to help? ##

Please do! We are always looking to improve this library. Please see our
[Contribution Guidelines](https://github.com/dockyard/openid_connect/blob/master/CONTRIBUTING.md)
on how to properly submit issues and pull requests.

## Legal ##

[DockYard](http://dockyard.com/), Inc. &copy; 2018

[@dockyard](http://twitter.com/dockyard)

[Licensed under the MIT license](http://www.opensource.org/licenses/mit-license.php)
