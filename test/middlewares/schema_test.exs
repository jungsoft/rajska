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
  end

  defmodule NotStruct do
    def hello, do: :world
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

  test "Raises if scope module is not a struct" do
    assert_raise(
      RuntimeError,
      ~r/Query get_user is configured incorrectly, :scope option Rajska.SchemaTest.NotStruct is not a struct/,
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
              middleware Rajska.QueryAuthorization, [permit: :user, scope: NotStruct]
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end
    )
  end

  @args_option_test_cases [
    {false, :arg},
    {false, [:arg1, :arg2]},
    {false, %{arg: :arg}},
    {false, %{arg: [:arg]}},
    # This is not the correct usage of &Access.all/0 that is going to be used in the Kernel.get_in/2 in
    # Rajska.QueryScopeAuthorization.get_scope_field_value/2, but this is necessary because it's not possible to use
    # Access.all() (the correct usage). But for testing purpose only this is fine.
    {false, %{arg: [&Access.all/0, :arg]}},
    {true, "args"},
    {true, 1},
    {true, ["args"]},
    {true, [1]},
    {true, %{arg: ["arg"]}},
    {true, %{arg: [1]}},
    {true, [&Access.all/0, :arg]},
  ]

  for {{should_raise, args_value}, index} <- Enum.with_index(@args_option_test_cases) do
    @should_raise should_raise
    @args_value args_value
    @index index
    @base_message "if args option is #{inspect(args_value)}"
    @message if should_raise, do: "Raises #{@base_message}", else: "Not raises #{@base_message}"

    test @message do
      args_value = @args_value
      index = @index

      define_query_fn = fn ->
        defmodule String.to_atom("SchemaInvalidArgs#{index}") do
          use Absinthe.Schema

          @args_value args_value

          def context(ctx), do: Map.put(ctx, :authorization, Authorization)

          def middleware(middleware, field, %{identifier: identifier})
          when identifier in [:query, :mutation] do
            Rajska.add_query_authorization(middleware, field, Authorization)
          end

          def middleware(middleware, _field, _object), do: middleware

          query do
            field :get_user, :string do
              middleware Rajska.QueryAuthorization, [permit: :user, scope: User, args: @args_value]
              resolve fn _args, _info -> {:ok, "bob"} end
            end
          end
        end
      end

      if @should_raise do
        invalid_value = if is_map(@args_value), do: @args_value[:arg], else: @args_value
        escaped_invalid_value = invalid_value |> inspect() |> Regex.escape()

        assert_raise(
          RuntimeError,
          ~r/Query get_user is configured incorrectly, the following args option is invalid: #{escaped_invalid_value}/,
          define_query_fn
        )
      else
        define_query_fn.()
      end
    end
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

  test "Does not break and skips middleware check for subscriptions" do
    defmodule SchemaWithSubscription do
      use Absinthe.Schema

      def middleware(middleware, field, %{identifier: identifier})
      when identifier in [:query, :mutation] do
        Rajska.add_query_authorization(middleware, field, Authorization)
      end

      def middleware(middleware, _field, _object), do: middleware

      object :user do
        field :email, :string
        field :name, :string
      end

      mutation do
        field :create_user, :user do
          middleware Rajska.QueryAuthorization, permit: :user, scope: false
          resolve fn _args, _info -> {:ok, %{email: "email", name: "name"}} end
        end
      end

      query do
        field :get_user, :user do
          middleware Rajska.QueryAuthorization, permit: :user, scope: false
          resolve fn _args, _info -> {:ok, %{email: "email", name: "name"}} end
        end
      end

      subscription do
        field :new_users, :user do
          arg :email, non_null(:string)

          config fn args, _info -> {:ok, topic: args.email} end
        end
      end
    end
  end

  test "Adds object authorization after query authorization" do
    defmodule SchemaQueryAndObjectAuthorization do
      use Absinthe.Schema

      def context(ctx), do: Map.put(ctx, :authorization, Authorization)

      def middleware(middleware, field, %{identifier: identifier})
      when identifier in [:query, :mutation] do
        middleware
        |> Rajska.add_query_authorization(field, Authorization)
        |> Rajska.add_object_authorization()
        |> check_middlewares()
      end

      def middleware(middleware, _field, _object), do: middleware

      def check_middlewares(middlewares) do
        assert [
          {Absinthe.Middleware.Telemetry, []},
          {{Rajska.QueryAuthorization, :call}, [permit: :all]},
          Rajska.ObjectAuthorization,
          {{Absinthe.Resolution, :call}, _fn}
        ] = middlewares
      end

      query do
        field :get_user, :string do
          middleware Rajska.QueryAuthorization, permit: :all
          resolve fn _args, _info -> {:ok, "bob"} end
        end
      end
    end
  end

  test "Adds object authorization before resolution when there is no query authorization" do
    defmodule SchemaObjectAuthorization do
      use Absinthe.Schema

      def context(ctx), do: Map.put(ctx, :authorization, Authorization)

      def middleware(middleware, _field, %{identifier: identifier})
      when identifier in [:query, :mutation] do
        middleware
        |> Rajska.add_object_authorization()
        |> check_middlewares()
      end

      def middleware(middleware, _field, _object), do: middleware

      def check_middlewares(middlewares) do
        assert [
          {Absinthe.Middleware.Telemetry, []},
          Rajska.ObjectAuthorization,
          {{Absinthe.Resolution, :call}, _fn}
        ] = middlewares
      end

      query do
        field :get_user, :string do
          resolve fn _args, _info -> {:ok, "bob"} end
        end
      end
    end
  end
end
