defmodule Rajska.FieldAuthorizationTest do
  use ExUnit.Case, async: true

  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_roles: [:admin]
  end

  defmodule Schema do
    use Absinthe.Schema

    def context(ctx), do: Map.put(ctx, :authorization, Authorization)

    def middleware(middleware, field, %{identifier: identifier} = object)
    when identifier not in [:query, :mutation, :subscription] do
      Rajska.add_field_authorization(middleware, field, object)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :get_user, :user do
        arg :id, non_null(:integer)
        arg :is_email_public, non_null(:boolean)

        resolve fn args, _ ->
          {:ok, %{
            id: args.id,
            name: "bob",
            is_email_public: args.is_email_public,
            phone: "123456",
            email: "bob@email.com"
          }} end
      end
    end

    object :user do
      meta :scope_by, :id

      field :name, :string
      field :is_email_public, :boolean

      field :phone, :string, meta: [private: true]
      field :email, :string, meta: [private: & !&1.is_email_public]
    end
  end

  test "User can access own fields" do
    user = %{role: :user, id: 1}
    get_user_query = get_user_query(1, false)

    {:ok, result} = Absinthe.run(get_user_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"getUser" => data}} = result
    refute Map.has_key?(result, :errors)

    assert is_binary(data["name"])
    assert is_binary(data["email"])
    assert is_binary(data["phone"])
  end

  test "User cannot access other user private fields" do
    user = %{role: :user, id: 1}
    get_user_query = get_user_query(2, false)

    {:ok, %{
      errors: errors,
      data: %{"getUser" => data}
    }} = Absinthe.run(get_user_query, __MODULE__.Schema, context: %{current_user: user})

    error_messages = Enum.map(errors, & &1.message)
    assert Enum.member?(error_messages, "Not authorized to access field phone")
    assert Enum.member?(error_messages, "Not authorized to access field email")

    assert is_binary(data["name"])
    assert data["phone"] === nil
    assert data["email"] === nil
  end

  test "Admin can access all fields" do
    user = %{role: :admin, id: 3}
    get_user_query = get_user_query(2, false)

    {:ok, result} = Absinthe.run(get_user_query, __MODULE__.Schema, context: %{current_user: user})

    assert %{data: %{"getUser" => data}} = result
    refute Map.has_key?(result, :errors)

    assert is_binary(data["name"])
    assert is_binary(data["email"])
    assert is_binary(data["phone"])
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
end
