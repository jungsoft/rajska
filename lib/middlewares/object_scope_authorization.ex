defmodule Rajska.ObjectScopeAuthorization do
  @behaviour Absinthe.Middleware

  alias Absinthe.{
    Resolution,
    Schema,
    Type
  }

  def call(%Resolution{definition: definition} = resolution, _config) do
    authorize(definition.schema_node.type, definition.selections, resolution)
  end

  defp authorize(type, fields, resolution, nested_keys \\ []) do
    type
    |> lookup_object(resolution.schema)
    |> authorize_object(fields, resolution, nested_keys)
  end

  # When is a list, inspect object that composes the list.
  defp lookup_object(%Type.List{of_type: object_type}, schema) do
    lookup_object(object_type, schema)
  end

  defp lookup_object(object_type, schema) do
    Schema.lookup_type(schema, object_type)
  end

  # When is an user defined object, lookup the scope meta tag.
  defp authorize_object(object, fields, resolution, nested_keys) do
    object
    |> Type.meta(:scope)
    |> is_authorized?(resolution, object, nested_keys)
    |> put_result(fields, resolution, object, nested_keys)
  end

  defp is_authorized?(nil, _, object, _nested_keys), do: raise "No meta scope defined for object #{inspect object.identifier}"

  defp is_authorized?(false, resolution, _object, _nested_keys), do: resolution

  defp is_authorized?({scoped_struct, field}, resolution, _object, nested_keys) do
    field = nested_keys ++ [field]
    apply_authorization!(resolution, scoped_struct, field)
  end

  defp is_authorized?(scoped_struct, resolution, _object, nested_keys) do
    apply_authorization!(resolution, scoped_struct, nested_keys ++ [:id])
  end

  defp apply_authorization!(resolution, scoped_struct, scoped_field) do
    scoped_field = List.wrap(scoped_field)
    scoped_field_value = resolution |> Map.get(:value) |> get_in(scoped_field)

    Rajska.apply_auth_mod(resolution, :has_resolution_access?, [resolution, scoped_struct, scoped_field_value])
  end

  defp put_result(true, fields, resolution, _type, nested_keys), do: find_associations(fields, resolution, nested_keys)

  defp put_result(false, _fields, resolution, object, _nested_keys) do
    Resolution.put_result(resolution, {:error, "Not authorized to access object #{object.identifier}"})
  end

  defp find_associations([%{selections: []} | tail], resolution, nested_keys) do
    find_associations(tail, resolution, nested_keys)
  end

  defp find_associations(
    [%{schema_node: schema_node, selections: selections} | tail],
    resolution,
    nested_keys
  ) do
    authorize(schema_node.type, selections ++ tail, resolution, nested_keys ++ [schema_node.identifier])
  end

  defp find_associations([], resolution, _nested_keys), do: resolution
end
