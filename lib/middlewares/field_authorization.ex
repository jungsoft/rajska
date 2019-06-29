defmodule Rajska.FieldAuthorization do
  @moduledoc """
    Absinthe middleware to ensure field permissions.
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.{
    Resolution,
    Type
  }

  def call(resolution, [object: %{fields: fields} = object, field: field]) do
    is_field_private? = fields[field] |> Type.meta(:private) |> is_field_private?(resolution.source)
    scope_by = get_scope_by_field(object, is_field_private?)

    resolution
    |> authorized?(is_field_private?, scope_by, resolution.source)
    |> put_result(resolution, field)
  end

  defp is_field_private?(true, _source), do: true
  defp is_field_private?(private, source) when is_function(private), do: private.(source)
  defp is_field_private?(_private, _source), do: false

  defp get_scope_by_field(_object, false), do: :ok

  defp get_scope_by_field(object, _private) do
    case Type.meta(object, :scope_by) do
      nil -> raise "No scope_by meta defined for object returned from query #{object.identifier}"
      scope_by_field when is_atom(scope_by_field) -> scope_by_field
    end
  end

  defp authorized?(_resolution, false, _scope_by, _source), do: true

  defp authorized?(resolution, true, scope_by, source) do
    case Rajska.apply_auth_mod(resolution, :is_super_user?, [resolution]) do
      true -> true
      false -> Rajska.apply_auth_mod(resolution, :is_field_authorized?, [resolution, scope_by, source])
    end
  end

  defp put_result(true, resolution, _field), do: resolution

  defp put_result(false, resolution, field) do
    Resolution.put_result(resolution, {:error, "Not authorized to access field #{field}"})
  end
end
