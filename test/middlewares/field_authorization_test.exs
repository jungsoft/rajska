defmodule Rajska.FieldAuthorizationTest do
  use ExUnit.Case, async: true

  defmodule User do
    defstruct [
      id: 1,
      name: "User",
      email: "email@user.com",
      phone: "123456",
      is_email_public: true,
      always_private: "private!"
    ]
  end

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin

    def has_user_access?(_current_user, User, _field, :private), do: false
    def has_user_access?(%{role: :admin}, User, _field, :default), do: true
    def has_user_access?(%{id: user_id}, User, {:id, id}, :default) when user_id === id, do: true
    def has_user_access?(_current_user, User, _field, :default), do: false
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, field, %{identifier: identifier} = object)
    when identifier not in [:query, :mutation] do
      Rajska.add_field_authorization(middleware, field, object)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :get_user, :user do
        arg :id, non_null(:integer)
        arg :is_email_public, non_null(:boolean)

        resolve fn args, _ ->
          {:ok, %User{
            id: args.id,
            name: "bob",
            is_email_public: args.is_email_public,
            phone: "123456",
            email: "bob@email.com",
            always_private: "private!",
          }} end
      end

      field :get_field_scope_user, :field_scope_user do
        arg :id, non_null(:integer)

        resolve fn args, _ ->
          {:ok, %User{
            id: args.id,
            name: "bob",
            phone: "123456",
          }} end
      end

      field :get_not_scoped, :not_scoped do
        resolve fn _args, _ -> {:ok, %{phone: "123456"}} end
      end

      field :get_both_scopes, :both_scopes do
        resolve fn _args, _ -> {:ok, %{phone: "123456"}} end
      end
    end

    object :user do
      meta :scope_by, :id

      field :name, :string
      field :is_email_public, :boolean

      field :phone, :string, meta: [private: true]
      field :email, :string, meta: [private: & !&1.is_email_public]
      field :always_private, :string, meta: [private: true, rule: :private]
    end

    object :field_scope_user do
      meta :scope_field_by, :id

      field :name, :string
      field :phone, :string, meta: [private: true]
    end

    object :not_scoped do
      field :phone, :string, meta: [private: true]
    end

    object :both_scopes do
      meta :scope_by, :id
      meta :scope_field_by, :id

      field :phone, :string, meta: [private: true]
    end
  end

  test "User can access own fields" do
    get_user_query = get_user_query(1, false)

    {:ok, result} = Absinthe.run(get_user_query, __MODULE__.Schema, context(:user, 1))

    assert %{data: %{"getUser" => data}} = result
    refute Map.has_key?(result, :errors)

    assert is_binary(data["name"])
    assert is_binary(data["email"])
    assert is_binary(data["phone"])
  end

  test "Custom rules are applied" do
    {:ok, %{
      errors: errors,
      data: %{"getUser" => data}
    }} = Absinthe.run(get_user_private_query(1), __MODULE__.Schema, context(:user, 1))

    error_messages = Enum.map(errors, & &1.message)
    assert Enum.member?(error_messages, "Not authorized to access field always_private")

    assert is_nil(data["alwaysPrivate"])
  end

  test "User cannot access other user private fields" do
    get_user_query = get_user_query(2, false)

    {:ok, %{
      errors: errors,
      data: %{"getUser" => data}
    }} = Absinthe.run(get_user_query, __MODULE__.Schema, context(:user, 1))

    error_messages = Enum.map(errors, & &1.message)
    assert Enum.member?(error_messages, "Not authorized to access field phone")
    assert Enum.member?(error_messages, "Not authorized to access field email")

    assert is_binary(data["name"])
    assert data["phone"] === nil
    assert data["email"] === nil
  end

  test "Admin can access all fields" do
    get_user_query = get_user_query(2, false)
    {:ok, result} = Absinthe.run(get_user_query, __MODULE__.Schema, context(:admin, 3))

    assert %{data: %{"getUser" => data}} = result
    refute Map.has_key?(result, :errors)

    assert is_binary(data["name"])
    assert is_binary(data["email"])
    assert is_binary(data["phone"])
  end

  test "Works when defining scope_field_by" do
    user = %{role: :user, id: 1}
    get_user_query = get_field_scope_user(2)

    {:ok, %{
      errors: errors,
      data: %{"getFieldScopeUser" => data}
    }} = Absinthe.run(get_user_query, __MODULE__.Schema, context: %{current_user: user})

    error_messages = Enum.map(errors, & &1.message)
    assert Enum.member?(error_messages, "Not authorized to access field phone")

    assert is_binary(data["name"])
    assert data["phone"] === nil
  end

  test "Raises when no meta scope_by or scope_field_by is defined for an object" do
    assert_raise RuntimeError, ~r/No meta scope_by or scope_field_by defined for object :not_scoped/, fn ->
      Absinthe.run("{ getNotScoped { phone } }", __MODULE__.Schema, context(:user, 2))
    end
  end

  test "Raises when both scope metas are defined for an object" do
    assert_raise RuntimeError, ~r/Error in :both_scopes. If scope_field_by is defined, then scope_by must not be defined/, fn ->
      Absinthe.run("{ getBothScopes { phone } }", __MODULE__.Schema, context(:user, 2))
    end
  end

  defp get_user_query(id, is_email_public) do
    """
    {
      getUser(id: #{id}, isEmailPublic: #{is_email_public}) {
        name
        email
        phone
        isEmailPublic
      }
    }
    """
  end

  defp get_field_scope_user(id) do
    """
    {
      getFieldScopeUser(id: #{id}) {
        name
        phone
      }
    }
    """
  end

  defp get_user_private_query(id) do
    """
    {
      getUser(id: #{id}, isEmailPublic: true) {
        alwaysPrivate
      }
    }
    """
  end

  defp context(role, id), do: [context: %{current_user: %{role: role, id: id}}]
end
