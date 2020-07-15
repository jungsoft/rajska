if Code.ensure_loaded?(Hammer) do
  defmodule Rajska.RateLimiter do
    @moduledoc """
    Rate limiter absinthe middleware. Uses [Hammer](https://github.com/ExHammer/hammer).

    ## Usage

    First configure Hammer, following its documentation. For example:

        config :hammer,
        backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 4,
                                      cleanup_interval_ms: 60_000 * 10]}

    Add your middleware to the query that should be limited:

        field :default_config, :string do
          middleware Rajska.RateLimiter
          resolve fn _, _ -> {:ok, "ok"} end
        end

    You can also configure it and use multiple rules for limiting in one query:

        field :login_user, :session do
          arg :email, non_null(:string)
          arg :password, non_null(:string)

          middleware Rajska.RateLimiter, limit: 10 # Using the default identifier (user IP)
          middleware Rajska.RateLimiter, keys: :email, limit: 5 # Using the value provided in the email arg
          resolve &AccountsResolver.login_user/2
        end

    The allowed configuration are:

    * `scale_ms`: The timespan for the maximum number of actions. Defaults to 60_000.
    * `limit`: The maximum number of actions in the specified timespan. Defaults to 10.
    * `id`: An atom or string to be used as the bucket identifier. Note that this will always be the same, so by using this the limit will be global instead of by user.
    * `keys`: An atom or a list of atoms to get a query argument as identifier. Use a list when the argument is nested.
    * `error_msg`: The error message to be displayed when rate limit exceeds. Defaults to `"Too many requests"`.

    Note that when neither `id` or `keys` is provided, the default is to use the user's IP. For that, the default behaviour is to use
    `c:Rajska.Authorization.get_ip/1` to fetch the IP from the absinthe context. That means you need to manually insert the user's IP in the
    absinthe context before using it as an identifier. See the [absinthe docs](https://hexdocs.pm/absinthe/context-and-authentication.html#content)
    for more information.
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

    defp get_identifier(%Resolution{context: context}, nil, nil),
      do: Rajska.apply_auth_mod(context, :get_ip, [context])

    defp get_identifier(%Resolution{arguments: arguments}, keys, nil),
      do: get_in(arguments, List.wrap(keys)) || raise "Invalid configuration in Rate Limiter. Key not found in arguments."

    defp get_identifier(%Resolution{}, nil, id), do: id

    defp get_identifier(%Resolution{}, _keys, _id), do: raise "Invalid configuration in Rate Limiter. If key is defined, then id must not be defined"
  end
end
