defmodule Rajska.ObjectAuthorization do
  @moduledoc """
    Middleware to block access to private objects.
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.{
    Resolution,
    Schema,
    Type
  }
  alias Type.{Custom, Scalar}

  def call(%{state: :resolved} = resolution, _config), do: resolution

  def call(%{definition: definition} = resolution, _config) do
    authorize(definition.schema_node.type, definition.selections, resolution)
  end

  defp authorize(type, fields, resolution) do
    type
    |> lookup_object()
    |> authorize_object(fields, resolution)
  end

  # When is a list, inspect object that composes the list.
  defp lookup_object(%Type.List{of_type: object_type}) do
    lookup_object(object_type)
  end

  defp lookup_object(object_type) do
    Schema.lookup_type(Rajska.get_schema(), object_type)
  end

  # When is a Scalar, Custom or Enum type, authorize.
  defp authorize_object(%type{} = object, fields, resolution)
  when type in [Scalar, Custom, Type.Enum, Type.Enum.Value] do
    put_result(true, fields, resolution, object)
  end

  # When is an user defined object, lookup the authorize meta tag.
  defp authorize_object(object, fields, resolution) do
    object
    |> Type.meta(:authorize)
    |> is_authorized?(resolution, object)
    |> put_result(fields, resolution, object)
  end

  defp is_authorized?(nil, _, object), do: raise "No meta authorize defined for object #{inspect object.identifier}"

  defp is_authorized?(permission, resolution, _object) do
    Rajska.apply_config_mod(:is_authorized?, [resolution, permission])
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
end
