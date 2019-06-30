defmodule Rajska.ObjectAuthorization do
  @moduledoc """
  Absinthe middleware to ensure object permissions.

  Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the permission defined in each object meta `authorize`.

  ## Usage

  ```elixir
  object :wallet_balance do
    meta :authorize, :admin

    field :total, :integer
  end

  object :company do
    meta :authorize, :user

    field :name, :string

    field :wallet_balance, :wallet_balance
  end

  object :user do
    meta :authorize, :all

    field :email, :string

    field :company, :company
  end
  ```

  With the permissions above, a query like the following would only be allowed by an admin user:

  ```graphql
  {
    userQuery {
      name
      email
      company {
        name
        walletBalance { total }
      }
    }
  }
  ```

  Object Authorization middleware runs after Query Authorization middleware (if added) and before the query is resolved by recursively checking the requested objects permissions in the [is_authorized?/2](https://hexdocs.pm/rajska) function (which is also used by Query Authorization). It can be overridden by your own implementation.
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
    Rajska.apply_auth_mod(resolution, :is_resolution_authorized?, [resolution, permission])
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
