defmodule Rajska.ObjectAuthorizationTest do
  use ExUnit.Case, async: true

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation] do
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
        middleware Rajska.QueryAuthorization, [permit: :user, scope: false]
        resolve fn _, _ ->
          {:ok, %{
            name: "bob",
            company: %{name: "company"},
            wallet_balance: %{total: 10}
          }}
        end
      end

      field :enum_query, :role_enum do
        middleware Rajska.QueryAuthorization, [permit: :all, scope: false]
        resolve fn _, _ ->
          {:ok, :user}
        end
      end

      field :union_query, :union do
        middleware Rajska.QueryAuthorization, [permit: :all, scope: false]
        resolve fn _, _ ->
          {:ok, %{name: "bob"}}
        end
      end

      field :interface_query, :interface do
        middleware Rajska.QueryAuthorization, [permit: :all, scope: false]
        resolve fn _, _ ->
          {:ok, %{name: "bob"}}
        end
      end
    end

    object :wallet_balance do
      meta :authorize, :admin
      interfaces([:interface])

      field :total, :integer
    end

    object :company do
      meta :authorize, :user

      field :name, :string

      field :wallet_balance, :wallet_balance
    end

    enum :role_enum do
      value :user
      value :admin
    end

    object :user do
      meta :authorize, :all
      interfaces([:interface])

      field :email, :string
      field :name, :string

      field :company, :company
    end

    union :union do
      types [:wallet_balance, :user]
      resolve_type fn
        %{name: _}, _ -> :user
        %{total: _}, _ -> :wallet_balance
      end
    end

    interface :interface do
      resolve_type fn
        %{name: _}, _ -> :user
        %{total: _}, _ -> :wallet_balance
      end
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
        locations: [%{column: 3, line: 2}],
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
        locations: [%{column: 3, line: 2}],
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

  test "Query that returns an enum doesn't return errors" do
    {:ok, result} = Absinthe.run(enum_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"enumQuery" => "USER"}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Works for union types" do
    {:ok, result} = Absinthe.run(union_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"unionQuery" => %{"name" => "bob"}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Works for interfaces" do
    {:ok, result} = Absinthe.run(interface_query(), __MODULE__.Schema, context: %{current_user: %{role: :admin}})

    assert %{data: %{"interfaceQuery" => %{"name" => "bob"}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Works when using fragments and user has access" do
    {:ok, result} = Absinthe.run(fragment_query_user(), __MODULE__.Schema, context: %{current_user: %{role: :user}})

    assert %{data: %{"userQuery" => %{"name" => "bob", "company" => %{}}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Returns error when using fragments and user does not have access" do
    assert {:ok, %{errors: errors}} = Absinthe.run(fragment_query_admin(), __MODULE__.Schema, context: %{current_user: %{role: :user}})
    assert [
      %{
        locations: [%{column: 3, line: 13}],
        message: "Not authorized to access object wallet_balance",
        path: ["userQuery"]
      }
    ] == errors
  end

  test "does not apply when resolution is already resolved" do
    resolution = %Absinthe.Resolution{state: :resolved}
    assert resolution == Rajska.ObjectAuthorization.call(resolution, [])
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

  defp enum_query, do:  "{ enumQuery }"

  defp union_query do
    """
    {
      unionQuery {
        ... on User {
          name
        }
        ... on WalletBalance {
          total
        }
      }
    }
    """
  end

  defp interface_query do
    """
    {
      interfaceQuery {
        ... on User {
          name
        }
        ... on WalletBalance {
          total
        }
      }
    }
    """
  end

  defp fragment_query_user do
    """
    fragment userFields on User {
      name
      company {
        name
      }
    }
    {
      userQuery {
        ...userFields
      }
    }
    """
  end

  defp fragment_query_admin do
    """
    fragment companyFields on Company {
      walletBalance {
        total
      }
    }
    fragment userFields on User {
      name
      company {
        ...companyFields
      }
    }
    {
      userQuery {
        ...userFields
      }
    }
    """
  end
end
