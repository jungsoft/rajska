defmodule Rajska.QueryPermitterTest do
  use Absinthe.Case, async: true

  defmodule Authorization do
    use Rajska,
      otp_app: :my_app,
      roles: [:user, :admin],
      all_role: :all
  end

  Application.put_env(Rajska, :configurator, Authorization)

  defmodule User do
    defstruct name: "User", email: "email@user.com"

    def __schema__(:source), do: "users"
  end

  defmodule Schema do
    use Absinthe.Schema

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation, :subscription] do
      Rajska.add_authentication_middleware(middleware, field)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :all_query, :user do
        middleware Rajska.QueryPermitter, permit: :all
        resolve fn _, _ ->
          {:ok, %{name: "bob"}}
        end
      end

      field :user_query, :user do
        middleware Rajska.QueryPermitter, [permit: :user, scoped: false]
        resolve fn _, _ ->
          {:ok, %{name: "bob"}}
        end
      end

      field :admin_query, :user do
        middleware Rajska.QueryPermitter, permit: :admin
        resolve fn _, _ ->
          {:ok, %{name: "bob"}}
        end
      end
    end

    object :user do
      field :email, :string
      field :name, :string
    end
  end

  Application.put_env(Rajska, :schema, Schema)

  test "Admin query fails for unauthenticated user" do
    assert {:ok, %{errors: errors}} = Absinthe.run(admin_query(), __MODULE__.Schema, context: %{current_user: nil})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "unauthorized",
        path: ["adminQuery"]
      }
    ] == errors
  end

  test "Admin query fails for user" do
    assert {:ok, %{errors: errors}} = Absinthe.run(admin_query(), __MODULE__.Schema, context: %{current_user: %{role: :user}})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "unauthorized",
        path: ["adminQuery"]
      }
    ] == errors
  end

  test "Admin query works for admin" do
    {:ok, result} = Absinthe.run(admin_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"adminQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User query fails for unauthenticated user" do
    assert {:ok, %{errors: errors}} = Absinthe.run(user_query(), __MODULE__.Schema, context: %{current_user: nil})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "unauthorized",
        path: ["userQuery"]
      }
    ] == errors
  end

  test "User query works for user" do
    {:ok, result} = Absinthe.run(user_query(), __MODULE__.Schema, context: %{current_user: %{role: :user}})

    assert %{data: %{"userQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User query works for admin" do
    {:ok, result} = Absinthe.run(user_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"userQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "All query works for unauthenticated user" do
    {:ok, result} = Absinthe.run(all_query(), __MODULE__.Schema, context: %{current_user: nil})

    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "All query works for user" do
    {:ok, result} = Absinthe.run(all_query(), __MODULE__.Schema, context: %{current_user: %{role: :user}})

    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "All query works for admin" do
    {:ok, result} = Absinthe.run(all_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  defp admin_query, do: "{ adminQuery { name email } }"

  defp user_query, do: "{ userQuery { name email } }"

  defp all_query, do: "{ allQuery { name email } }"
end
