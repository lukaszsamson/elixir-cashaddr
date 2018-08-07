defmodule CashAddr.MixProject do
  use Mix.Project

  @version "1.0.1"
  @source_url "https://github.com/lukaszsamson/elixir-cashaddr"

  def project do
    [
      app: :cashaddr,
      version: @version,
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      name: "CashAddr",
      source_url: @source_url,
      docs: [
        extras: ["README.md"],
        main: "readme",
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    []
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.19", only: :dev}
    ]
  end

  defp description do
    """
    Library for decoding and validating CashAddr btc cash addresses.
    """
  end

  defp package do
    [
      name: :cashaddr,
      files: ["lib", "mix.exs", ".formatter.exs", "README*", "LICENSE*"],
      maintainers: ["Łukasz Samson"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
