defmodule Rajska.ObjectAuthorizationTest do
  use Absinthe.Case, async: true

  defmodule Authorization do
    use Rajska,
      otp_app: :my_app,
      roles: [:user, :admin]
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation, :subscription] do
      middleware
      |> Rajska.add_query_authorization(field, Authorization)
      |> Rajska.add_object_authorization()
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :all_query, :user do
        middleware Rajska.QueryAuthorization, permit: :all
        resolve fn _, _ ->
          {:ok, %{
            name: "bob",
            company: %{name: "company"},
            wallet_balance: %{total: 10}
          }}
        end
      end

      field :user_query, :user do
        middleware Rajska.QueryAuthorization, [permit: :user, scoped: false]
        resolve fn _, _ ->
          {:ok, %{
            name: "bob",
            company: %{name: "company"},
            wallet_balance: %{total: 10}
          }}
        end
      end
    end

    object :wallet_balance do
      meta :authorize, :admin

      field :total, :integer
    end

    object :company do
      meta :authorize, :user

      field :name, :string

      field :wallet_balance, :wallet_balance
    end

    object :user do
      meta :authorize, :all

      field :email, :string
      field :name, :string

      field :company, :company
    end
  end

  test "Public query with public object works for everyone" do
    {:ok, result} = Absinthe.run(all_query(), __MODULE__.Schema, context: %{current_user: nil})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = Absinthe.run(all_query(), __MODULE__.Schema, context: %{current_user: %{role: :user}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = Absinthe.run(all_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Public query with user object works for user" do
    {:ok, result} = Absinthe.run(all_query_with_user_object(), __MODULE__.Schema, context: %{current_user: %{role: :user}})

    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Public query with user object fails for unauthenticated user" do
    assert {:ok, %{errors: errors}} = Absinthe.run(all_query_with_user_object(), __MODULE__.Schema, context: %{current_user: nil})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object company",
        path: ["allQuery"]
      }
    ] == errors
  end

  test "User query with user object works for user" do
    {:ok, result} = Absinthe.run(user_query_with_user_object(), __MODULE__.Schema, context: %{current_user: %{role: :user}})

    assert %{data: %{"userQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User query with user object works for admin" do
    {:ok, result} = Absinthe.run(user_query_with_user_object(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"userQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User query with admin object fails for user" do
    assert {:ok, %{errors: errors}} = Absinthe.run(user_query_with_admin_object(), __MODULE__.Schema, context: %{current_user: %{role: :user}})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object wallet_balance",
        path: ["userQuery"]
      }
    ] == errors
  end

  test "User query with admin object works for admin" do
    {:ok, result} = Absinthe.run(user_query_with_admin_object(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"userQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  defp all_query do
    """
    {
      allQuery {
        name
        email
      }
    }
    """
  end

  defp all_query_with_user_object do
    """
    {
      allQuery {
        name
        email
        company {
          name
        }
      }
    }
    """
  end

  defp user_query_with_user_object do
    """
    {
      userQuery {
        name
        email
        company { name }
      }
    }
    """
  end

  defp user_query_with_admin_object do
    """
    {
      userQuery {
        name
        email
        company {
          name
          walletBalance { total }
        }
      }
    }
    """
  end
end
