defmodule Rajska.QueryAuthorization do
  @moduledoc """
    Verifies if query is permitted according to user role.
  """
  alias Absinthe.Resolution

  alias Rajska.ScopeAuthorization

  @behaviour Absinthe.Middleware

  def call(resolution, [{:permit, permission} | _scoped] = config) do
    validate_permission!(resolution, permission)

    resolution
    |> Rajska.apply_auth_mod(:is_authorized?, [resolution, permission])
    |> update_result(resolution)
    |> ScopeAuthorization.call(config)
  end

  defp validate_permission!(resolution, permitted_roles) do
    valid_roles = Rajska.apply_auth_mod(resolution, :valid_roles)

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

  defp update_result(false, resolution) do
    Resolution.put_result(resolution, {:error, Rajska.apply_auth_mod(resolution, :unauthorized_msg)})
  end
end
