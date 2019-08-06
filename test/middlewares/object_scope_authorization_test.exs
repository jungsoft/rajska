defmodule Rajska.ObjectScopeAuthorizationTest do
  use Absinthe.Case, async: true

  defmodule User do
    defstruct [
      id: 1,
      name: "User",
      email: "email@user.com"
    ]

    def __schema__(:source), do: "users"
  end

  defmodule Authorization do
    use Rajska,
      roles: [:user, :admin]

    def has_user_access?(%{role: :admin}, User, _id), do: true
    def has_user_access?(%{id: user_id}, User, id) when user_id === id, do: true
    def has_user_access?(_current_user, User, _id), do: false
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, _field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation, :subscription] do
      Rajska.add_object_scope_auhtorization(middleware)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :all_query, :user do
        middleware Rajska.QueryAuthorization, permit: :all
        resolve fn _, _ ->
          {:ok, %{
            id: 1,
            name: "bob",
            company: %{name: "company"},
            wallet_balance: %{total: 10}
          }}
        end
      end
    end

    object :user do
      meta :authorize, :user
      meta :scope, {User, :id}

      field :id, :integer
      field :email, :string
      field :name, :string
    end
  end

  test "Only user with same ID and admin has access to scoped user" do
    {:ok, result} = Absinthe.run(all_query_with_user_object(), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 1}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = Absinthe.run(all_query_with_user_object(), __MODULE__.Schema, context: %{current_user: %{role: :admin, id: 2}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = Absinthe.run(all_query_with_user_object(), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 2}})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object user",
        path: ["allQuery"]
      }
    ] == errors
  end

  defp all_query_with_user_object do
    """
    {
      allQuery {
        name
        email
      }
    }
    """
  end
end
