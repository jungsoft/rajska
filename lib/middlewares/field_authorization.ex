defmodule Rajska.FieldAuthorization do
  @moduledoc """
    Middleware to block access to private fields.
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.{
    Resolution,
    Type
  }

  def call(resolution, [object: object, field: field]) do
    is_private = Type.meta(object.fields[field], :private) || false
    scope_by = get_scope_by_field(object, is_private)

    resolution
    |> authorized?(is_private, scope_by, resolution.source)
    |> put_result(resolution, field)
  end

  defp get_scope_by_field(_object, false), do: :ok

  defp get_scope_by_field(_object, private) when is_function(private), do: :ok

  defp get_scope_by_field(object, true) do
    case Type.meta(object, :scope_by) do
      nil -> raise "No scope_by meta defined for object returned from query #{object.identifier}"
      scope_by_field when is_atom(scope_by_field) -> scope_by_field
    end
  end

  defp authorized?(_resolution, false, _scope_by, _source), do: true

  defp authorized?(resolution, private, scope_by, source) do
    case Rajska.apply_auth_mod(resolution, :is_super_user?, [resolution]) do
      true -> resolution
      false -> is_user_authorized?(resolution, private, scope_by, source)
    end
  end

  defp is_user_authorized?(_resolution, private, _scope_by, source) when is_function(private), do: private.(source)

  defp is_user_authorized?(resolution, true, scope_by, source) do
    current_user = Rajska.apply_auth_mod(resolution, :get_current_user, [resolution])
    current_user_id = current_user && Map.get(current_user, :id)

    current_user_id === Map.get(source, scope_by)
  end

  defp put_result(true, resolution, _field), do: resolution

  defp put_result(false, resolution, field) do
    Resolution.put_result(resolution, {:error, "Not authorized to access field #{field}"})
  end
end
