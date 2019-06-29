use Mix.Config

config :logger, level: :debug

import_config "#{Mix.env()}.exs"
