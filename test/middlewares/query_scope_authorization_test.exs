defmodule Rajska.QueryScopeAuthorizationTest do
  use ExUnit.Case, async: true

  defmodule User do
    defstruct [
      id: 1,
      name: "User",
      email: "email@user.com"
    ]
  end

  defmodule BankAccount do
    defstruct [
      id: 1,
      total: 5,
    ]
  end

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin

    def has_user_access?(%{role: :admin}, %User{}, :default), do: true
    def has_user_access?(%{id: user_id}, %User{id: id}, :default) when user_id === id, do: true
    def has_user_access?(_current_user, %User{}, :default), do: false

    def has_user_access?(_current_user, %BankAccount{}, :edit), do: false
    def has_user_access?(_current_user, %BankAccount{}, :read_only), do: true
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation] do
      Rajska.add_query_authorization(middleware, field, Authorization)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :user_scoped_query, :user do
        arg :id, non_null(:integer)

        middleware Rajska.QueryAuthorization, [permit: :user, scope: User]
        resolve fn _, _ ->
          {:ok, %{
            name: "bob",
            bank_account: %{id: 1, total: 10}
          }} end
      end

      field :custom_arg_scoped_query, :user do
        arg :user_id, non_null(:integer)

        middleware Rajska.QueryAuthorization, [
          permit: :user,
          scope: User,
          args: %{id: :user_id}
        ]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :custom_nested_arg_scoped_query, :user do
        arg :params, non_null(:user_params)

        middleware Rajska.QueryAuthorization, [
          permit: :user,
          scope: User,
          args: %{id: [:params, :id]}
        ]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :custom_nested_optional_arg_scoped_query, :user do
        arg :params, non_null(:user_params)

        middleware Rajska.QueryAuthorization, [
          permit: :user,
          scope: User,
          args: %{id: [:params, :id]},
          optional: true
        ]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :not_scoped_query, :user do
        arg :id, non_null(:integer)

        middleware Rajska.QueryAuthorization, [permit: :user, scope: false]
        resolve fn _, _ -> {:ok, %{name: "bob"}} end
      end

      field :scoped_bank_account_update_mutation, :bank_account do
        arg :id, :integer
        arg :params, :bank_account_params

        middleware Rajska.QueryAuthorization, [permit: :user, scope: BankAccount, rule: :edit]
        resolve fn _, _ -> {:ok, %{total: 100}} end
      end
    end

    object :user do
      field :email, :string
      field :name, :string
      field :bank_account, :bank_account
    end

    object :bank_account do
      meta :scope, {BankAccount, :user_id}
      meta :rule, :read_only

      field :total, :integer
    end

    input_object :user_params do
      field :id, :integer
    end

    input_object :bank_account_params do
      field :total, :integer
    end
  end

  test "User can see bank_account but not edit it" do
    user = %{role: :user, id: 1}

    {:ok, success_result} = Absinthe.run(user_scoped_query(1), __MODULE__.Schema, context: %{current_user: user})

    refute Map.has_key?(success_result, :errors)

    assert {:ok,
      %{
        errors: [
          %{
            message: "Not authorized to access this bank account",
          }
        ]
      }
    } = Absinthe.run(scoped_bank_account_update_mutation(1), __MODULE__.Schema, context: %{current_user: user})
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

  test "User scoped query with custom nested argument works for own user" do
    user = %{role: :user, id: 1}
    custom_nested_arg_scoped_query = custom_nested_arg_scoped_query(1)

    {:ok, result} = Absinthe.run(custom_nested_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"customNestedArgScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User scoped query with custom nested argument fails for own user if argument is not provided" do
    user = %{role: :user, id: 1}
    custom_nested_arg_scoped_query = custom_nested_arg_scoped_query(nil)

    assert_raise RuntimeError, "Error in query customNestedArgScopedQuery: no argument [:params, :id] found in %{params: %{id: nil}}", fn ->
      Absinthe.run(custom_nested_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})
    end
  end

  test "User scoped query with custom optional nested argument works for own user if argument is not provided" do
    user = %{role: :user, id: 1}
    custom_nested_optional_arg_scoped_query = custom_nested_optional_arg_scoped_query(nil)

    {:ok, result} = Absinthe.run(custom_nested_optional_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"customNestedOptionalArgScopedQuery" => %{}}} = result
    refute Map.has_key?(result, :errors)
  end

  test "User scoped query with custom optional nested argument works for own user if argument is provided" do
    user = %{role: :user, id: 1}
    custom_nested_optional_arg_scoped_query = custom_nested_optional_arg_scoped_query(1)

    {:ok, result} = Absinthe.run(custom_nested_optional_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"customNestedOptionalArgScopedQuery" => %{}}} = result
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

  test "User scoped query with custom nested argument fails for different user" do
    user = %{role: :user, id: 2}
    custom_nested_arg_scoped_query = custom_nested_arg_scoped_query(1)

    assert {:ok, %{errors: errors}} = Absinthe.run(custom_nested_arg_scoped_query, __MODULE__.Schema, context: %{current_user: user})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "Not authorized to access this user",
        path: ["customNestedArgScopedQuery"]
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
    { userScopedQuery(id: #{user_id}) { name email bank_account { total } } }
    """
  end

  def custom_arg_scoped_query(user_id) do
    """
    { customArgScopedQuery(userId: #{user_id}) { name email } }
    """
  end

  def custom_nested_arg_scoped_query(user_id) do
    user_id = if user_id == nil, do: "null", else: user_id
    """
    { customNestedArgScopedQuery(params: {id: #{user_id}}) { name email } }
    """
  end

  def custom_nested_optional_arg_scoped_query(user_id) do
    user_id = if user_id == nil, do: "null", else: user_id
    """
    { customNestedOptionalArgScopedQuery(params: {id: #{user_id}}) { name email } }
    """
  end

  def not_scoped_query(user_id) do
    """
    { notScopedQuery(id: #{user_id}) { name email } }
    """
  end

  def scoped_bank_account_update_mutation(bank_account_id) do
    bank_account_id = if bank_account_id == nil, do: "null", else: bank_account_id
    """
    { scopedBankAccountUpdateMutation(id: #{bank_account_id}, params: {total: 100}) { total } }
    """
  end
end
