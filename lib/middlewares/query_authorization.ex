defmodule Rajska.QueryAuthorization do
  @moduledoc """
  Absinthe middleware to ensure query permissions.

  ## Usage

  [Create your Authorization module and add it and QueryAuthorization to your Absinthe.Schema](https://hexdocs.pm/rajska/Rajska.html#module-usage). Then set the permitted role to access a query or mutation:

  ```elixir
  mutation do
    field :create_user, :user do
      arg :params, non_null(:user_params)

      middleware Rajska.QueryAuthorization, permit: :all
      resolve &AccountsResolver.create_user/2
    end

    field :update_user, :user do
      arg :id, non_null(:integer)
      arg :params, non_null(:user_params)

      middleware Rajska.QueryAuthorization, [permit: :user, scope: User] # same as [permit: :user, scope: User, args: :id]
      resolve &AccountsResolver.update_user/2
    end

    field :delete_user, :user do
      arg :id, non_null(:integer)

      middleware Rajska.QueryAuthorization, permit: :admin
      resolve &AccountsResolver.delete_user/2
    end
  end
  ```

  Query authorization will call `c:Rajska.Authorization.role_authorized?/2` to check if the [user](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:get_current_user/1) [role](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:get_user_role/1) is authorized to perform the query.
  """
  alias Absinthe.Resolution

  alias Rajska.QueryScopeAuthorization

  @behaviour Absinthe.Middleware

  def call(%{context: context} = resolution, [{:permit, permission} | _scope] = config) do
    validate_permission!(context, permission)

    context
    |> Rajska.apply_auth_mod(:context_role_authorized?, [context, permission])
    |> update_result(resolution)
    |> QueryScopeAuthorization.call(config)
  end

  defp validate_permission!(context, permitted_roles) do
    valid_roles = Rajska.apply_auth_mod(context, :valid_roles)

    unless permission_valid?(valid_roles, permitted_roles) do
      raise """
        Invalid permission passed to QueryAuthorization: #{inspect(permitted_roles)}.
        Allowed permission: #{inspect(valid_roles)}.
      """
    end
  end

  defp permission_valid?(valid_roles, permitted_roles) when is_list(permitted_roles) do
    Enum.all?(permitted_roles, & permission_valid?(valid_roles, &1))
  end

  defp permission_valid?(valid_roles, permitted_role) when is_atom(permitted_role) do
    Enum.member?(valid_roles, permitted_role)
  end

  defp update_result(true, resolution), do: resolution

  defp update_result(false, %{context: context} = resolution) do
    Resolution.put_result(resolution, {:error, Rajska.apply_auth_mod(context, :unauthorized_msg, [resolution])})
  end
end
