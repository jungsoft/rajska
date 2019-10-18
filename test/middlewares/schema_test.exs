defmodule Rajska.SchemaTest do
  use ExUnit.Case, async: true

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin
  end

  defmodule User do
    defstruct [
      id: 1,
      name: "User",
      email: "email@user.com"
    ]

    def __schema__(:source), do: "users"
  end

  test "Raises if no permission is specified for a query" do
    assert_raise RuntimeError, ~r/No permission specified for query get_user/, fn ->
      defmodule SchemaNoPermission do
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
      ~r/Query get_user is configured incorrectly, :scope option must be present for role :user/,
      fn ->
        defmodule SchemaNoScope do
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
        defmodule SchemaNoScopeRuntime do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, permit: :user
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end

        {:ok, _result} = Absinthe.run("{ getUser }", SchemaNoScopeRuntime, context: %{current_user: %{role: :user}})
      end
    )
  end

  test "Raises if no permit key is specified for a query" do
    assert_raise RuntimeError, ~r/Query get_user is configured incorrectly, :permit option must be present/, fn ->
      defmodule SchemaNoPermit do
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

  test "Raises if scope module doesn't implement a __schema__(:source) function" do
    assert_raise(
      RuntimeError,
      ~r/Query get_user is configured incorrectly, :scope option :invalid_module doesn't implement a __schema__/,
      fn ->
        defmodule SchemaNoStruct do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          def middleware(middleware, field, %{identifier: identifier})
          when identifier in [:query, :mutation] do
            Rajska.add_query_authorization(middleware, field, Authorization)
          end

          def middleware(middleware, _field, _object), do: middleware

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, [permit: :user, scope: :invalid_module]
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end
    )
  end

  test "Raises if args option is invalid" do
    assert_raise(
      RuntimeError,
      ~r/Query get_user is configured incorrectly, the following args option is invalid: "args"/,
      fn ->
        defmodule SchemaInvalidArgs do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          def middleware(middleware, field, %{identifier: identifier})
          when identifier in [:query, :mutation] do
            Rajska.add_query_authorization(middleware, field, Authorization)
          end

          def middleware(middleware, _field, _object), do: middleware

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, [permit: :user, scope: User, args: "args"]
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end
    )
  end

  test "Raises if optional option is not a boolean" do
    assert_raise(
      RuntimeError,
      ~r/Query get_user is configured incorrectly, :optional option must be a boolean./,
      fn ->
        defmodule SchemaInvalidOptional do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          def middleware(middleware, field, %{identifier: identifier})
          when identifier in [:query, :mutation] do
            Rajska.add_query_authorization(middleware, field, Authorization)
          end

          def middleware(middleware, _field, _object), do: middleware

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, [permit: :user, scope: User, optional: :invalid]
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end
    )
  end

  test "Raises if rule option is not an atom" do
    assert_raise(
      RuntimeError,
      ~r/Query get_user is configured incorrectly, :rule option must be an atom./,
      fn ->
        defmodule SchemaInvalidRule do
          use Absinthe.Schema

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          def middleware(middleware, field, %{identifier: identifier})
          when identifier in [:query, :mutation] do
            Rajska.add_query_authorization(middleware, field, Authorization)
          end

          def middleware(middleware, _field, _object), do: middleware

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, [permit: :user, scope: User, rule: 4]
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end
    )
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
