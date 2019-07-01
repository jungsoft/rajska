defmodule Rajska.ScopeAuthorizationTest do
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

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation, :subscription] do
      Rajska.add_query_authorization(middleware, field, Authorization)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :user_scoped_query, :user do
        arg :id, non_null(:integer)

        middleware Rajska.QueryAuthorization, [permit: :user, scoped: User]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :custom_arg_scoped_query, :user do
        arg :user_id, non_null(:integer)

        middleware Rajska.QueryAuthorization, [permit: :user, scoped: {User, :user_id}]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :not_scoped_query, :user do
        arg :id, non_null(:integer)

        middleware Rajska.QueryAuthorization, [permit: :user, scoped: false]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end
    end

    object :user do
      field :email, :string
      field :name, :string
    end
  end

  test "User scoped query works for own user" do
    user = %{role: :user, id: 1}
    user_scoped_query = user_scoped_query(1)

    {:ok, result} = Absinthe.run(user_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"userScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User scoped query works for admin user" do
    user = %{role: :admin, id: 3}
    user_scoped_query = user_scoped_query(1)

    {:ok, result} = Absinthe.run(user_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"userScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User scoped query fails for different user" do
    user = %{role: :user, id: 2}
    user_scoped_query = user_scoped_query(1)

    assert {:ok, %{errors: errors}} = Absinthe.run(user_scoped_query, __MODULE__.Schema, context: %{current_user: user})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "Not authorized to access this user",
        path: ["userScopedQuery"]
      }
    ] == errors
  end

  test "User scoped query with custom argument works for own user" do
    user = %{role: :user, id: 1}
    custom_arg_scoped_query = custom_arg_scoped_query(1)

    {:ok, result} = Absinthe.run(custom_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"customArgScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User scoped query with custom argument works for admin user" do
    user = %{role: :admin, id: 3}
    custom_arg_scoped_query = custom_arg_scoped_query(1)

    {:ok, result} = Absinthe.run(custom_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"customArgScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User scoped query with custom argument fails for different user" do
    user = %{role: :user, id: 2}
    custom_arg_scoped_query = custom_arg_scoped_query(1)

    assert {:ok, %{errors: errors}} = Absinthe.run(custom_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "Not authorized to access this user",
        path: ["customArgScopedQuery"]
      }
    ] == errors
  end

  test "Not scoped query works for any user" do
    not_scoped_query = not_scoped_query(1)

    user = %{role: :user, id: 1}
    assert {:ok, result} = Absinthe.run(not_scoped_query, __MODULE__.Schema, context: %{current_user: user})
    assert %{data: %{"notScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    user2 = %{role: :user, id: 2}
    assert {:ok, result2} = Absinthe.run(not_scoped_query, __MODULE__.Schema, context: %{current_user: user2})
    assert %{data: %{"notScopedQuery" => %{}}} = result2
    refute Map.has_key?(result2, :errors)

    admin = %{role: :admin, id: 3}
    assert {:ok, admin_result} = Absinthe.run(not_scoped_query, __MODULE__.Schema, context: %{current_user: admin})
    assert %{data: %{"notScopedQuery" => %{}}} = admin_result
    refute Map.has_key?(admin_result, :errors)
  end

  defp user_scoped_query(user_id) do
    """
    { userScopedQuery(id: #{user_id}) { name email } }
    """
  end

  def custom_arg_scoped_query(user_id) do
    """
    { customArgScopedQuery(userId: #{user_id}) { name email } }
    """
  end

  def not_scoped_query(user_id) do
    """
    { notScopedQuery(id: #{user_id}) { name email } }
    """
  end
end
