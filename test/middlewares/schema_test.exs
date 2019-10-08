defmodule Rajska.SchemaTest do
  use ExUnit.Case, async: true

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin
  end

  test "Raises if no permission is specified for a query" do
    assert_raise RuntimeError, ~r/No permission specified for query get_user/, fn ->
      defmodule Schema do
        use Absinthe.Schema

        def context(ctx), do: Map.put(ctx, :authorization, Authorization)

        def middleware(middleware, field, %{identifier: identifier})
        when identifier in [:query, :mutation] do
          Rajska.add_query_authorization(middleware, field, Authorization)
        end

        def middleware(middleware, _field, _object), do: middleware

        query do
          field :get_user, :string do
            resolve fn _args, _info -> {:ok, "bob"} end
          end
        end
      end
    end
  end

  test "Raises in compile time if no scope key is specified for a scope role" do
    assert_raise(
      RuntimeError,
      ~r/Query get_user is configured incorrectly, :scope option must be present for role user/,
      fn ->
        defmodule Schema do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          def middleware(middleware, field, %{identifier: identifier})
          when identifier in [:query, :mutation] do
            Rajska.add_query_authorization(middleware, field, Authorization)
          end

          def middleware(middleware, _field, _object), do: middleware

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, permit: :user
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end
    )
  end

  test "Raises in runtime if no scope key is specified for a scope role" do
    assert_raise(
      RuntimeError,
      ~r/Error in query getUser: no scope argument found in middleware Scope Authorization/,
      fn ->
        defmodule Schema do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, permit: :user
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end

        {:ok, _result} = Absinthe.run("{ getUser }", Schema, context: %{current_user: %{role: :user}})
      end
    )
  end

  test "Raises if no permit key is specified for a query" do
    assert_raise RuntimeError, ~r/Query get_user is configured incorrectly, permit option must be present/, fn ->
      defmodule Schema do
        use Absinthe.Schema

        def context(ctx), do: Map.put(ctx, :authorization, Authorization)

        def middleware(middleware, field, %{identifier: identifier})
        when identifier in [:query, :mutation] do
          Rajska.add_query_authorization(middleware, field, Authorization)
        end

        def middleware(middleware, _field, _object), do: middleware

        query do
          field :get_user, :string do
            middleware Rajska.QueryAuthorization, permt: :all
            resolve fn _args, _info -> {:ok, "bob"} end
          end
        end
      end
    end
  end

  test "Raises if no authorization module is found in absinthe's context" do
    assert_raise RuntimeError, ~r/Rajska authorization module not found in Absinthe's context/, fn ->
      defmodule Schema do
        use Absinthe.Schema

        def middleware(middleware, field, %{identifier: identifier})
        when identifier in [:query, :mutation] do
          Rajska.add_query_authorization(middleware, field, Authorization)
        end

        def middleware(middleware, _field, _object), do: middleware

        query do
          field :get_user, :string do
            middleware Rajska.QueryAuthorization, permit: :all
            resolve fn _args, _info -> {:ok, "bob"} end
          end
        end
      end

      {:ok, _result} = Absinthe.run("{ getUser }", Schema, context: %{current_user: nil})
    end
  end
end
