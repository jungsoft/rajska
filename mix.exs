defmodule Rajska.MixProject do
  use Mix.Project

  @github_url "https://github.com/jungsoft/rajska"

  def project do
    [
      app: :rajska,
      version: "1.3.3",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Rajska",
      source_url: @github_url,
      description: "Rajska is an authorization library for Absinthe.",
      package: package(),
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

  defp deps do
    [
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:credo, "~> 1.6.0", only: [:dev, :test], runtime: false},
      {:absinthe, "~> 1.5.4 or ~> 1.6.0 or ~> 1.7"},
      {:excoveralls, "~> 0.11", only: :test},
      {:hammer, "~> 6.0", optional: true},
      {:mock, "~> 0.3.0", only: :test}
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
