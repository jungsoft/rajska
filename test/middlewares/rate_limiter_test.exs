defmodule Rajska.RateLimiterTest do
  use ExUnit.Case, async: false

  import Mock

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    input_object :keys_params do
      field :id, :string
    end

    query do
      field :default_config, :string do
        middleware Rajska.RateLimiter
        resolve fn _, _ -> {:ok, "ok"} end
      end

      field :scale_limit, :string do
        middleware Rajska.RateLimiter, scale_ms: 30_000, limit: 5
        resolve fn _, _ -> {:ok, "ok"} end
      end

      field :id, :string do
        middleware Rajska.RateLimiter, id: :custom_id
        resolve fn _, _ -> {:ok, "ok"} end
      end

      field :key, :string do
        arg :id, :string

        middleware Rajska.RateLimiter, keys: :id
        resolve fn _, _ -> {:ok, "ok"} end
      end

      field :keys, :string do
        arg :params, :keys_params
        middleware Rajska.RateLimiter, keys: [:params, :id]
        resolve fn _, _ -> {:ok, "ok"} end
      end

      field :id_and_key, :string do
        middleware Rajska.RateLimiter, id: :id, keys: :keys
        resolve fn _, _ -> {:ok, "ok"} end
      end

      field :error_msg, :string do
        middleware Rajska.RateLimiter, error_msg: "Rate limit exceeded"
        resolve fn _, _ -> {:ok, "ok"} end
      end
    end
  end

  @default_context [context: %{ip: "ip"}]

  setup_with_mocks([{Hammer, [], [check_rate: fn _a, _b, _c -> {:allow, 1} end]}]) do
    :ok
  end

  test "works with default configs" do
    {:ok, _} = Absinthe.run(query(:default_config), __MODULE__.Schema, @default_context)
    assert_called Hammer.check_rate("query:ip", 60_000, 10)
  end

  test "accepts scale and limit configuration" do
    {:ok, _} = Absinthe.run(query(:scale_limit), __MODULE__.Schema, @default_context)
    assert_called Hammer.check_rate("query:ip", 30_000, 5)
  end

  test "accepts id configuration" do
    {:ok, _} = Absinthe.run(query(:id), __MODULE__.Schema, @default_context)
    assert_called Hammer.check_rate("query:custom_id", 60_000, 10)
  end

  test "accepts key configuration" do
    {:ok, _} = Absinthe.run(query(:key, :id, "id_key"), __MODULE__.Schema, @default_context)
    assert_called Hammer.check_rate("query:id_key", 60_000, 10)
  end

  test "throws error if key is not present" do
    assert_raise RuntimeError, ~r/Invalid configuration in Rate Limiter. Key not found in arguments./, fn ->
      Absinthe.run(query(:key), __MODULE__.Schema, @default_context)
    end
  end

  test "accepts key configuration for nested parameters" do
    {:ok, _} = Absinthe.run(query(:keys, :params, %{id: "id_key"}), __MODULE__.Schema, @default_context)
    assert_called Hammer.check_rate("query:id_key", 60_000, 10)
  end

  test "throws error when id and key are provided as configuration" do
    assert_raise RuntimeError, ~r/Invalid configuration in Rate Limiter. If key is defined, then id must not be defined/, fn ->
      Absinthe.run(query(:id_and_key), __MODULE__.Schema, @default_context)
    end
  end

  test "accepts error msg configuration" do
    with_mock Hammer, [check_rate: fn _a, _b, _c -> {:deny, 1} end] do
      assert {:ok, %{errors: errors}} = Absinthe.run(query(:error_msg), __MODULE__.Schema, @default_context)
      assert [
        %{
          locations: [%{column: 3, line: 1}],
          message: "Rate limit exceeded",
          path: ["error_msg"]
        }
      ] == errors
    end
  end

  test "does not apply when resolution is already resolved" do
    resolution = %Absinthe.Resolution{state: :resolved}
    assert resolution == Rajska.RateLimiter.call(resolution, [])
  end

  defp query(name), do: "{ #{name} }"
  defp query(name, key, value) when is_binary(value), do: "{ #{name}(#{key}: \"#{value}\") }"
  defp query(name, key, %{} = value), do: "{ #{name}(#{key}: {#{build_arguments(value)}}) }"

  defp build_arguments(arguments) do
    arguments
    |> Enum.map(fn {k, v} -> if is_nil(v), do: nil, else: "#{k}: #{inspect(v, [charlists: :as_lists])}" end)
    |> Enum.reject(&is_nil/1)
    |> Enum.join(", ")
  end
end
