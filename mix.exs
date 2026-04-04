defmodule Rajska.MixProject do
  use Mix.Project

  @github_url "https://github.com/jungsoft/rajska"

  def project do
    [
      app: :rajska,
      version: "1.3.2",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Rajska",
      source_url: @github_url,
      description: "Rajska is an authorization library for Absinthe.",
      package: package(),
      docs: docs(),
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "test.all": :test
      ]
    ]
  end

  def elixirc_paths(:test), do: ["lib", "test/support"]
  def elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp package do
    [
      files: ~w(lib mix.exs README* LICENSE*),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @github_url,
        "Docs" => "https://hexdocs.pm/rajska/"
      }
    ]
  end

  defp docs do
    [main: "readme", extras: ["README.md"]]
  end

  defp deps do
    [
      {:absinthe, System.get_env("ABSINTHE_VERSION", "~> 1.4.0 or ~> 1.5.4 or ~> 1.6")},
      {:hammer, "~> 6.0", optional: true},

      # dev and test deps
      {:excoveralls, "~> 0.18", only: :test},
      {:mock, "~> 0.3.0", only: :test},
      {:ex_doc, "~> 0.34.2", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      "test.all": [
        "credo --strict",
        "test"
      ]
    ]
  end
end
