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

    def has_user_access?(%{role: :admin}, Company, _id), do: true
    def has_user_access?(%{id: user_id}, Company, company_user_id) when user_id === company_user_id, do: true
    def has_user_access?(_current_user, Company, _id), do: false

    def has_user_access?(%{role: :admin}, Wallet, _id), do: true
    def has_user_access?(%{id: user_id}, Wallet, id) when user_id === id, do: true
    def has_user_access?(_current_user, Wallet, _id), do: false
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
        arg :user_id, non_null(:integer)

        middleware Rajska.QueryAuthorization, permit: :all
        resolve fn args, _ ->
          {:ok, %{
            id: args.user_id,
            name: "bob",
            company: %{
              id: 5,
              user_id: args.user_id,
              name: "company",
              wallet: %{id: 1, total: 10}
            }
          }}
        end
      end
    end

    object :user do
      meta :scope, User

      field :id, :integer
      field :email, :string
      field :name, :string

      field :company, :company
    end

    object :company do
      meta :scope, {Company, :user_id}

      field :id, :integer
      field :user_id, :integer
      field :name, :string
      field :wallet, :wallet
    end

    object :wallet do
      meta :scope, Wallet

      field :total, :integer
    end
  end

  test "Only user with same ID and admin has access to scoped user" do
    {:ok, result} = Absinthe.run(all_query(1), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 1}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = Absinthe.run(all_query(1), __MODULE__.Schema, context: %{current_user: %{role: :admin, id: 2}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = Absinthe.run(all_query(1), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 2}})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object user",
        path: ["allQuery"]
      }
    ] == errors
  end

  test "Only user that owns the company and admin can access it" do
    {:ok, result} = Absinthe.run(all_query_with_company(1), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 1}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = Absinthe.run(all_query_with_company(1), __MODULE__.Schema, context: %{current_user: %{role: :admin, id: 2}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = Absinthe.run(all_query_with_company(1), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 2}})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object user",
        path: ["allQuery"]
      }
    ] == errors
  end

  test "Works for deeply nested objects" do
    assert {:ok, %{errors: errors}} = Absinthe.run(all_query_company_wallet(2), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 2}})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object wallet",
        path: ["allQuery"]
      }
    ] == errors

    {:ok, result} = Absinthe.run(all_query_company_wallet(2), __MODULE__.Schema, context: %{current_user: %{role: :admin, id: 2}})
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = Absinthe.run(all_query_company_wallet(2), __MODULE__.Schema, context: %{current_user: %{role: :user, id: 1}})
    assert [
      %{
        locations: [%{column: 0, line: 2}],
        message: "Not authorized to access object user",
        path: ["allQuery"]
      }
    ] == errors
  end

  defp all_query(id) do
    """
    {
      allQuery(userId: #{id}) {
        name
        email
      }
    }
    """
  end

  defp all_query_with_company(id) do
    """
    {
      allQuery(userId: #{id}) {
        name
        email
        company {
          id
          name
        }
      }
    }
    """
  end

  defp all_query_company_wallet(id) do
    """
    {
      allQuery(userId: #{id}) {
        name
        email
        company {
          id
          name
          wallet {
            total
          }
        }
      }
    }
    """
  end
end
