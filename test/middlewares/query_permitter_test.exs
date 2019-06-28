defmodule Rajska.QueryPermitterTest do
  use Absinthe.Case, async: true

  defmodule Authentication do
    use Rajska,
      otp_app: :my_app,
      roles: [:user, :admin],
      all_role: :all
  end

  Application.put_env(Rajska, :configurator, Authentication)

  defmodule Schema do
    use Absinthe.Schema

    def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
    when identifier in [:query, :mutation, :subscription] do
      Rajska.add_authentication_middleware(middleware, field)
    end

    def middleware(middleware, _field, _object), do: middleware

    query do
      field :get_user, :user do
        middleware Rajska.QueryPermitter, permit: :admin
        resolve fn _, _ ->
          {:ok, %{name: "bob"}}
        end
      end
    end

    object :user do
      field :email, :string
      field :name, :string
    end
  end

  Application.put_env(Rajska, :schema, Schema)

  test "Admin query fails for user" do
    doc = """
    { getUser { name email } }
    """

    assert {:ok, %{errors: errors}} = Absinthe.run(doc, __MODULE__.Schema, context: %{current_user: %{role: :user}})
    assert [
      %{
        locations: [%{column: 0, line: 1}],
        message: "unauthorized",
        path: ["getUser"]
      }
    ] == errors
  end
end
