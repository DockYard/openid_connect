defmodule OpenidConnect.Mixfile do
  use Mix.Project

  def project do
    [app: :openid_connect,
     version: "0.1.0",
     elixir: "~> 1.3",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description(),
     package: package(),
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger, :httpoison, :poison, :jose]]
  end

  def description() do
    """
    OpenID Connect for Elixir
    """
  end

  def package() do
  [maintainers: ["Brian Cardarella"],
   licenses: ["MIT"],
   links: %{"GitHub" => "https://github.com/dockyard/openid_connect"}]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [{:httpoison, "~> 0.9.0"},
     {:poison, "~> 2.0"},
     {:jose, "~> 1.8"}]
  end
end
