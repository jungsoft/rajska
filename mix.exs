defmodule Rajska.MixProject do
  use Mix.Project

  def project do
    [
      app: :rajska,
      version: "0.3.1",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Rajska",
      source_url: "https://github.com/rschef/rajska",
      description: "Rajska is an authorization library for Absinthe.",
      package: package(),
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
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
        "GitHub" => "https://github.com/rschef/rajska",
        "Docs" => "https://hexdocs.pm/rajska/"
      }
    ]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:credo, "~> 1.0.0", only: [:dev, :test], runtime: false},
      {:absinthe, "~> 1.4.0"},
      {:excoveralls, "~> 0.11", only: :test},
    ]
  end
end
