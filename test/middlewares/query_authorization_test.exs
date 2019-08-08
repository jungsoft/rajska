defmodule Rajska.QueryAuthorizationTest do
  use ExUnit.Case, async: true

  defmodule Authorization do
    use Rajska,
      roles: [:viewer, :user, :admin]
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation, :subscription] do
      Rajska.add_query_authorization(middleware, field, Authorization)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :all_query, :user do
        middleware Rajska.QueryAuthorization, permit: :all
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :user_query, :user do
        middleware Rajska.QueryAuthorization, [permit: :user, scoped: false]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :user_viewer_query, :user do
        middleware Rajska.QueryAuthorization, [permit: [:viewer, :user], scoped: false]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :admin_query, :user do
        middleware Rajska.QueryAuthorization, permit: :admin
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end
    end

    object :user do
      field :email, :string
      field :name, :string
    end
  end

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

  test "User and viewer query works for both viewer and user" do
    {:ok, result} = Absinthe.run(user_viewer_query(), __MODULE__.Schema, context: %{current_user: %{role: :user}})

    assert %{data: %{"userViewerQuery" => %{}}} = result
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

  defp user_viewer_query, do: "{ userViewerQuery { name email } }"

  defp all_query, do: "{ allQuery { name email } }"
end
