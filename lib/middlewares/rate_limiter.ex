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
    identifier = get_identifier(resolution, config[:keys], config[:id])
    error_msg = Keyword.get(config, :error_msg, "Too many requests")

    case Hammer.check_rate("query:#{identifier}", scale_ms, limit) do
      {:allow, _count} -> resolution
      {:deny, _limit} -> Resolution.put_result(resolution, {:error, error_msg})
    end
  end

  defp get_identifier(%Resolution{context: context, arguments: arguments}, keys, id) do
    case {keys, id} do
      {nil, nil} -> Rajska.apply_auth_mod(context, :get_ip, [context])
      {keys, nil} -> get_in(arguments, List.wrap(keys)) || raise "Invalid configuration in Rate Limiter. Key not found in arguments."
      {nil, id} -> id
      {_key, _id} -> raise "Invalid configuration in Rate Limiter. If key is defined, then id must not be defined"
    end
  end
end
