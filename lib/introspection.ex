defmodule Rajska.Introspection do
  @moduledoc false

  alias Absinthe.Type

  @doc """
  Introspect the Absinthe Type to get the underlying object type
  """
  def get_object_type(%Type.List{of_type: object_type}), do: get_object_type(object_type)
  def get_object_type(%Type.NonNull{of_type: object_type}), do: get_object_type(object_type)
  def get_object_type(object_type), do: object_type
end
