defmodule Rajska.ObjectScopeAuthorizationTest do
  use ExUnit.Case, async: true

  defmodule Wallet do
    defstruct [
      id: 1,
      total: 10,
      user_id: nil
    ]
  end

  defmodule Company do
    defstruct [
      id: 1,
      name: "User",
      user_id: 1,
      wallet: %Wallet{}
    ]
  end

  defmodule User do
    defstruct [
      id: 1,
      name: "User",
      email: "email@user.com",
      company: nil,
      companies: [],
      not_scoped: nil,
    ]
  end

  defmodule NotScoped do
    defstruct [
      id: 1,
    ]
  end

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin

    def has_user_access?(%{role: :admin}, %User{}, :default), do: true
    def has_user_access?(%{id: user_id}, %User{id: id}, :default) when user_id === id, do: true
    def has_user_access?(_current_user, %User{}, :default), do: false
    def has_user_access?(_current_user, %User{}, :object), do: false

    def has_user_access?(%{role: :admin}, %Company{}, :default), do: true
    def has_user_access?(%{id: user_id}, %Company{user_id: company_user_id}, :default) when user_id === company_user_id, do: true
    def has_user_access?(_current_user, %Company{}, :default), do: false

    def has_user_access?(%{role: :admin}, %Wallet{}, :default), do: true
    def has_user_access?(%{id: user_id}, %Wallet{user_id: id}, :default) when user_id === id, do: true
    def has_user_access?(_current_user, %Wallet{}, :default), do: false
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :all_query, non_null(:user) do
        arg :user_id, non_null(:integer)

        resolve fn args, _ ->
          {:ok, %User{
            id: args.user_id,
            name: "bob",
            company: %Company{
              id: 5,
              user_id: args.user_id,
              name: "company",
              wallet: %Wallet{id: 1, total: 10}
            }
          }}
        end
      end

      field :all_query_no_company, :user do
        arg :user_id, non_null(:integer)

        resolve fn args, _ ->
          {:ok, %User{
            id: args.user_id,
            name: "bob"
          }}
        end
      end

      field :all_query_companies_list, :user do
        arg :user_id, non_null(:integer)

        resolve fn args, _ ->
          {:ok, %User{
            id: args.user_id,
            name: "bob",
            companies: [
              %Company{id: 1, user_id: args.user_id, wallet: %Wallet{id: 2, total: 10}},
              %Company{id: 2, user_id: args.user_id, wallet: %Wallet{id: 1, total: 10}},
            ]
          }}
        end
      end

      field :users_query, list_of(:user) do
        resolve fn _args, _ ->
          {:ok, [
            %User{id: 1, name: "bob"},
            %User{id: 2, name: "bob"},
          ]}
        end
      end

      field :nil_user_query, :user do
        resolve fn _args, _ ->
          {:ok, nil}
        end
      end

      field :user_query_with_rule, :user_rule do
        resolve fn _args, _ ->
          {:ok, %User{id: 1}}
        end
      end

      field :string_query, :string do
        resolve fn _args, _ ->
          {:ok, "STRING"}
        end
      end

      field :get_both_scopes, :both_scopes do
        resolve fn _args, _ -> {:ok, %User{}} end
      end

      field :get_object_scope_user, :object_scope_user do
        arg :id, non_null(:integer)
        resolve fn args, _ -> {:ok, %User{id: args.id}} end
      end
    end

    object :user do
      meta :scope?, true

      field :id, :integer
      field :email, :string
      field :name, :string

      field :company, :company
      field :companies, list_of(:company)
      field :not_scoped, :not_scoped
    end

    object :company do
      field :id, :integer
      field :user_id, :integer
      field :name, :string
      field :wallet, :wallet
    end

    object :wallet do
      field :total, :integer
    end

    object :not_scoped do
      meta :scope?, false
      field :name, :string
    end

    object :user_rule do
      meta :rule, :object

      field :id, :integer
    end

    object :both_scopes do
      meta :scope?, true
      meta :scope_object?, false

      field :name, :string
    end

    object :object_scope_user do
      meta :scope_object?, true

      field :id, :integer
    end
  end

  test "Only user with same ID and admin has access to scoped user" do
    {:ok, result} = run_pipeline(all_query(1), context(:user, 1))
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = run_pipeline(all_query(1), context(:admin, 2))
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = run_pipeline(all_query(1), context(:user, 2))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user",
      }
    ] == errors
  end

  test "Only user that owns the company and admin can access it" do
    {:ok, result} = run_pipeline(all_query_with_company(1), context(:user, 1))
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = run_pipeline(all_query_with_company(1), context(:admin, 2))
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = run_pipeline(all_query_with_company(1), context(:user, 2))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user",
      }
    ] == errors
  end

  test "Works when defining scope_object? and not scope?" do
    query = "{ getObjectScopeUser(id: 1) { id } }"
    {:ok, result} = run_pipeline(query, context(:user, 1))
    assert %{data: %{"getObjectScopeUser" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = run_pipeline(query, context(:admin, 2))
    assert %{data: %{"getObjectScopeUser" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = run_pipeline(query, context(:user, 2))
    assert [
      %{
        locations: [%{column: 3, line: 1}],
        message: "Not authorized to access object object_scope_user",
      }
    ] == errors
  end

  test "Works for deeply nested objects" do
    assert {:ok, %{errors: errors}} = run_pipeline(all_query_company_wallet(2), context(:user, 2))
    assert [
      %{
        locations: [%{column: 7, line: 8}],
        message: "Not authorized to access object wallet",
      }
    ] == errors

    {:ok, result} = run_pipeline(all_query_company_wallet(2), context(:admin, 2))
    assert %{data: %{"allQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = run_pipeline(all_query_company_wallet(2), context(:user, 1))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user",
      }
    ] == errors
  end

  test "Works when returned nested object is nil" do
    assert {:ok, result} = run_pipeline(all_query_no_company(2), context(:user, 2))
    assert %{data: %{"allQueryNoCompany" => %{}}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = run_pipeline(all_query_no_company(2), context(:admin, 2))
    assert %{data: %{"allQueryNoCompany" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = run_pipeline(all_query_no_company(2), context(:user, 1))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user",
      }
    ] == errors
  end

  test "Works when query returns nil" do
    assert {:ok, result} = run_pipeline(nil_user_query(), context(:user, 1))
    assert %{data: %{"nilUserQuery" => nil}} = result
    refute Map.has_key?(result, :errors)

    {:ok, result} = run_pipeline(nil_user_query(), context(:admin, 2))
    assert %{data: %{"nilUserQuery" => nil}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Works when returned nested object is a list" do
    assert {:ok, %{errors: errors}} = run_pipeline(all_query_companies_list(2), context(:user, 2))
    assert [
      %{
        locations: [%{column: 7, line: 8}],
        message: "Not authorized to access object wallet",
      }
    ] == errors

    {:ok, result} = run_pipeline(all_query_companies_list(2), context(:admin, 2))
    assert %{data: %{"allQueryCompaniesList" => %{}}} = result
    refute Map.has_key?(result, :errors)

    assert {:ok, %{errors: errors}} = run_pipeline(all_query_companies_list(2), context(:user, 1))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user",
      }
    ] == errors
  end

  test "Works when query returns a list" do
    assert {:ok, %{errors: errors}} = run_pipeline(users_query(), context(:user, 2))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user",
      }
    ] == errors

    {:ok, result} = run_pipeline(users_query(), context(:admin, 2))
    assert %{data: %{"usersQuery" => [_ | _]}} = result
    refute Map.has_key?(result, :errors)
  end

  test "accepts a meta rule" do
    assert {:ok, %{errors: errors}} = run_pipeline(user_query_with_rule(), context(:admin, 1))
    assert [
      %{
        locations: [%{column: 3, line: 2}],
        message: "Not authorized to access object user_rule",
      }
    ] == errors
  end

  test "ignores object when is a primitive" do
    assert {:ok, result} = run_pipeline(string_query(), context(:user, 1))
    assert %{data: %{"stringQuery" => "STRING"}} = result
    refute Map.has_key?(result, :errors)
  end

  test "Raises when both scope? metas are defined for an object" do
    assert_raise RuntimeError, ~r/Error in :both_scopes. If scope_object\? is defined, then scope\? must not be defined/, fn ->
      run_pipeline("{ getBothScopes { name } }", context(:user, 2))
    end
  end

  test "Skips introspection query" do
    {:ok, result} = run_pipeline(introspection_query(), context(:admin, 2))
    assert %{data: %{}} = result
    refute Map.has_key?(result, :errors)
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

  defp all_query_no_company(id) do
    """
    {
      allQueryNoCompany(userId: #{id}) {
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

  defp all_query_companies_list(id) do
    """
    {
      allQueryCompaniesList(userId: #{id}) {
        name
        email
        companies {
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

  defp users_query do
    """
    {
      usersQuery {
        name
        email
      }
    }
    """
  end

  defp nil_user_query do
    """
    {
      nilUserQuery {
        name
        email
      }
    }
    """
  end

  defp user_query_with_rule do
    """
    {
      userQueryWithRule {
        id
      }
    }
    """
  end

  defp string_query do
    """
    {
      stringQuery
    }
    """
  end

  defp introspection_query do
    """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
  end

  defp context(role, id), do: [context: %{current_user: %{role: role, id: id}}]

  defp run_pipeline(document, opts) do
    case Absinthe.Pipeline.run(document, pipeline(opts)) do
      {:ok, %{result: result}, _phases} ->
        {:ok, result}

      {:error, msg, _phases} ->
        {:error, msg}
    end
  end

  defp pipeline(options) do
    __MODULE__.Schema
    |> Absinthe.Pipeline.for_document(options)
    |> Absinthe.Pipeline.insert_after(Absinthe.Phase.Document.Execution.Resolution, Rajska.ObjectScopeAuthorization)
  end
end
