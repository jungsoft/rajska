defmodule Rajska.ObjectScopeAuthorization do
  @behaviour Absinthe.Middleware

  alias Absinthe.{
    Resolution,
    Schema,
    Type
  }
  alias Rajska.ScopeAuthorization
  alias Type.{Custom, Scalar}

  def call(%Resolution{definition: definition} = resolution, _config) do
    authorize(definition.schema_node.type, definition.selections, resolution)
  end

  defp authorize(type, fields, resolution) do
    type
    |> lookup_object(resolution.schema)
    |> authorize_object(fields, resolution)
  end

  # When is a list, inspect object that composes the list.
  defp lookup_object(%Type.List{of_type: object_type}, schema) do
    lookup_object(object_type, schema)
  end

  defp lookup_object(object_type, schema) do
    Schema.lookup_type(schema, object_type)
  end

  # When is an user defined object, lookup the scope meta tag.
  defp authorize_object(object, fields, resolution) do
    object
    |> Type.meta(:scope)
    |> is_authorized?(resolution, object)
    |> put_result(fields, resolution, object)
  end

  defp is_authorized?(nil, _, object), do: raise "No meta scope defined for object #{inspect object.identifier}"

  defp is_authorized?(false, resolution, _object), do: resolution

  defp is_authorized?({scoped_struct, field}, resolution, _object) do
    apply_authorization!(resolution, scoped_struct, field)
  end

  defp is_authorized?(scoped_struct, resolution, _object) do
    apply_authorization!(resolution, scoped_struct, :id)
  end

  defp apply_authorization!(resolution, scoped_struct, scoped_field) do
    scoped_field_value = resolution |> Map.get(:value) |> Map.get(scoped_field)

    resolution
    |> Rajska.apply_auth_mod(:has_resolution_access?, [resolution, scoped_struct, scoped_field_value])
  end

  defp put_result(true, fields, resolution, _type), do: find_associations(fields, resolution)

  defp put_result(false, _fields, resolution, object) do
    Resolution.put_result(resolution, {:error, "Not authorized to access object #{object.identifier}"})
  end

  defp find_associations([%{selections: []} | tail], resolution) do
    find_associations(tail, resolution)
  end

  defp find_associations(
    [%{schema_node: schema_node, selections: selections} | tail],
    resolution
  ) do
    authorize(schema_node.type, selections ++ tail, resolution)
  end

  defp find_associations([], resolution), do: resolution






  # def call(resolution, [object: %Type.Object{} = object]) do
  #   IO.inspect(object)
  #   IO.inspect(resolution.value)
  #   IO.inspect(resolution.definition.selections)
  #   IO.puts "#####"

  #   object
  #   |> Type.meta(:authorize)
  #   |> scope_object!(resolution, object)
  # end

  # # def call(resolution, config) do
  # #   IO.inspect(resolution.value)
  # #   IO.inspect(resolution.source)
  # #   IO.inspect(config)
  # # end

  # defp scope_object!([_ | [scope: false]], resolution, _object), do: resolution

  # defp scope_object!([_ | [scope: {scoped_struct, field}]], resolution, object) do
  #   apply_authorization!(resolution, scoped_struct, field, object)
  # end

  # defp scope_object!([_ | [scope: scoped_struct]], resolution, object) do
  #   apply_authorization!(resolution, scoped_struct, :id, object)
  # end

  # defp scope_object!(_config, resolution, object) do
  #   # raise "Error in object #{object.name}: Scope authorization improperly configured"
  #   resolution
  # end

  # defp apply_authorization!(resolution, scoped_struct, scoped_field, object) do
  #   scoped_field_value = resolution |> Map.get(:value) |> Map.get(scoped_field) |> IO.inspect()

  #   resolution
  #   |> Rajska.apply_auth_mod(:has_resolution_access?, [resolution, scoped_struct, scoped_field_value])
  #   |> update_result(resolution, object)
  # end

  # defp update_result(true, resolution, _object), do: resolution

  # defp update_result(false, resolution, object) do
  #   put_error(resolution, "Not authorized to access this #{object.name}")
  # end

  # defp update_result({:error, msg}, resolution, _object), do: put_error(resolution, msg)

  # defp put_error(resolution, message), do: Resolution.put_result(resolution, {:error, message})
end
