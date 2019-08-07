defmodule Rajska.ObjectScopeAuthorization do
  @moduledoc """
  Absinthe middleware to perform object scoping.

  Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the value of the field defined in each object meta `scope`.

  ## Usage

  [Create your Authorization module and add it and ObjectScopeAuthorization to your Absinthe.Schema](https://hexdocs.pm/rajska/Rajska.html#module-usage). Then set the scope of an object:

  ```elixir
  object :user do
    meta :scope, User # Same as meta :scope, {User, :id}

    field :id, :integer
    field :email, :string
    field :name, :string

    field :company, :company
  end

  object :company do
    meta :scope, {Company, :user_id}

    field :id, :integer
    field :user_id, :integer
    field :name, :string
    field :wallet, :wallet
  end

  object :wallet do
    meta :scope, Wallet

    field :total, :integer
  end
  ```

  To define custom rules for the scoping, use `c:Rajska.Authorization.has_user_access?/3`. For example:

  ```elixir
  defmodule Authorization do
    use Rajska,
      roles: [:user, :admin]

    def has_user_access?(%{role: :admin}, User, _id), do: true
    def has_user_access?(%{id: user_id}, User, id) when user_id === id, do: true
    def has_user_access?(_current_user, User, _id), do: false
  end
  ```
  """
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
    field_keys = nested_keys ++ [field]
    apply_authorization!(resolution, scoped_struct, field_keys)
  end

  defp is_authorized?(scoped_struct, resolution, _object, nested_keys) do
    apply_authorization!(resolution, scoped_struct, nested_keys ++ [:id])
  end

  defp apply_authorization!(resolution, scoped_struct, scoped_field_keys) do
    scoped_field_value = resolution |> Map.get(:value) |> get_in(scoped_field_keys)

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
