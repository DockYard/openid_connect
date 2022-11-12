defmodule OpenIDConnect.Mixfile do
  use Mix.Project

  @version "0.2.2"

  def project do
    [
      app: :openid_connect,
      version: @version,
      elixir: "~> 1.3",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      description: description(),
      package: package(),
      name: "OpenID Connect",
      deps: deps(),
      docs: docs(),
      name: "OpenID Connect",
      source_url: "https://github.com/DockYard/openid_connect"
    ]
  end

  # Specifies which paths to compile per environment
  defp elixirc_paths(:test), do: elixirc_paths(nil) ++ ["test/support"]
  defp elixirc_paths(_), do: ["lib"]
  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [extra_applications: [:logger]]
  end

  def description do
    """
    OpenID Connect for Elixir
    """
  end

  def docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      logo: "openid-logo.png",
      extras: ["README.md"]
    ]
  end

  def package do
    [
      maintainers: ["Brian Cardarella"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/DockYard/openid_connect"},
      files: ~w(lib mix.exs README.md LICENSE.md CHANGELOG.md)
    ]
  end

  defp deps do
    [
      {:httpoison, "~> 1.2"},
      {:jason, ">= 1.0.0"},
      {:jose, "~> 1.8"},
      {:earmark, "~> 1.2", only: :dev},
      {:ex_doc, "~> 0.18", only: :dev},
      {:mox, "~> 1.0", only: :test}
    ]
  end
end
