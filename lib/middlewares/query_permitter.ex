defmodule Rajska.QueryPermitter do
  @moduledoc """
    Verifies if query is permitted according to user role.
  """
  alias Absinthe.Resolution

  alias Rajska.ScopeAuthorization

  @behaviour Absinthe.Middleware

  def call(resolution, [{:permit, permission} | scope_config]) do
    validate_permission!(permission)

    :is_authorized?
    |> Rajska.apply_config_module([resolution, permission])
    |> update_result(resolution)
    |> ScopeAuthorization.call(scope_config)
  end

  defp validate_permission!(permitted_roles) do
    unless permission_valid?(permitted_roles) do
      raise """
        Invalid permission passed to QueryPermitter: #{inspect(permitted_roles)}.
        Allowed permission: #{inspect(Rajska.valid_roles())}.
      """
    end
  end

  defp permission_valid?(permitted_roles) when is_list(permitted_roles) do
    Enum.all?(permitted_roles, &permission_valid?/1)
  end

  defp permission_valid?(permitted_role) when is_atom(permitted_role) do
    Enum.member?(Rajska.valid_roles(), permitted_role)
  end

  defp update_result(true, resolution), do: resolution

  defp update_result(false, resolution) do
    Resolution.put_result(resolution, {:error, Rajska.unauthorized_msg()})
  end
end
