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

  Keep in mind that the `field_value` provided to `has_user_access?/3` can be `nil`. This case can be handled as you wish.
  For example, to not raise any authorization errors and just return `nil`:

  ```elixir
  defmodule Authorization do
    use Rajska,
      roles: [:user, :admin]

    def has_user_access?(_user, _, nil), do: true

    def has_user_access?(%{role: :admin}, User, _id), do: true
    def has_user_access?(%{id: user_id}, User, id) when user_id === id, do: true
    def has_user_access?(_current_user, User, _id), do: false
  end
  ```
  """

  alias Absinthe.{Blueprint, Phase, Type}
  use Absinthe.Phase

  @spec run(Blueprint.t() | Phase.Error.t(), Keyword.t()) :: {:ok, map}
  def run(%Blueprint{execution: execution} = bp, _options \\ []) do
    {:ok, %{bp | execution: process(execution)}}
  end

  defp process(%{validation_errors: [], result: result} = execution), do: %{execution | result: result(result, execution.context)}
  defp process(execution), do: execution

  # Root
  defp result(%{fields: fields, emitter: %{schema_node: %{identifier: identifier}}} = result, context)
  when identifier in [:query, :mutation, :subscription] do
    %{result | fields: walk_result(fields, context)}
  end

  # Object
  defp result(%{fields: fields, emitter: %{schema_node: schema_node} = emitter} = result, context) do
    type = get_object_type(schema_node.type)
    scope = Type.meta(type, :scope)

    case is_authorized?(scope, result.root_value, context, type) do
      true -> %{result | fields: walk_result(fields, context)}
      false -> Map.put(result, :errors, [error(emitter)])
    end
  end

  # List
  defp result(%{values: values} = result, context) do
    %{result | values: walk_result(values, context)}
  end

  # Leafs
  defp result(result, _context), do: result

  # When is a list, inspect object that composes the list.
  defp get_object_type(%Type.List{of_type: object_type}), do: object_type
  defp get_object_type(object_type), do: object_type

  defp walk_result(fields, context, new_fields \\ [])

  defp walk_result([], _context, new_fields), do: new_fields

  defp walk_result([field | fields], context, new_fields) do
    new_fields = [result(field, context) | new_fields]
    walk_result(fields, context, new_fields)
  end

  defp is_authorized?(nil, _values, _context, object), do: raise "No meta scope defined for object #{inspect object.identifier}"

  defp is_authorized?(false, _values, _context, _object), do: true

  defp is_authorized?({scoped_struct, field}, values, context, _object) do
    scoped_field_value = Map.get(values, field)
    Rajska.apply_auth_mod(context, :has_context_access?, [context, scoped_struct, scoped_field_value])
  end

  defp is_authorized?(scoped_struct, values, context, _object) do
    scoped_field_value = Map.get(values, :id)
    Rajska.apply_auth_mod(context, :has_context_access?, [context, scoped_struct, scoped_field_value])
  end

  defp error(%{source_location: location, schema_node: %{type: type}}) do
    %Phase.Error{
      phase: __MODULE__,
      message: "Not authorized to access object #{get_object_type(type).identifier}",
      locations: [location]
    }
  end
end
