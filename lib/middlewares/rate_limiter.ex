defmodule Rajska.RateLimiter do
  @moduledoc """
  Rate limiter absinthe middleware.
  """
  @behaviour Absinthe.Middleware

  alias Absinthe.Resolution

  def call(%Resolution{state: :resolved} = resolution, _config), do: resolution

  def call(%Resolution{} = resolution, config) do
    scale_ms = Keyword.get(config, :scale_ms, 60_000)
    limit = Keyword.get(config, :limit, 10)
    identifier = get_identifier(resolution, config[:key], config[:id]) |> IO.inspect()
    error_msg = Keyword.get(config, :error_msg, "Too many requests")

    case Hammer.check_rate("query:#{identifier}", scale_ms, limit) |> IO.inspect() do
      {:allow, _count} -> resolution
      {:deny, _limit} -> Resolution.put_result(resolution, {:error, error_msg})
    end
  end

  # Gets the identifier for the limit bucket.
  # Uses IP by default, or takes the field in arguments using the `key` configuration.
  defp get_identifier(%Resolution{context: context, arguments: arguments}, key, id) do
    case {key, id} do
      {nil, nil} -> Rajska.apply_auth_mod(context, :get_ip, [context])
      {key, nil} -> get_in(arguments, List.wrap(keys))
      {nil, id} -> id
      {_key, _id} -> raise "Invalid configuration in Rate Limiter. If key is defined, then id must not be defined"
    end
  end
end
