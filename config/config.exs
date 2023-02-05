import Config

config :logger, level: :debug

for config <- "../apps/*/config/config.exs" |> Path.expand(__DIR__) |> Path.wildcard() do
  import_config config
end
