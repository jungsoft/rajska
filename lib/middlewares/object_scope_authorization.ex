defmodule Rajska.ObjectScopeAuthorization do
  @moduledoc """
  Absinthe Phase to perform object scoping.

  Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the underlying struct.

  ## Usage

  [Create your Authorization module and add it and ObjectScopeAuthorization to your Absinthe Pipeline](https://hexdocs.pm/rajska/Rajska.html#module-usage). Then set the scope of an object:

  ```elixir
  object :user do
    # Turn on Object and Field scoping, but if the FieldAuthorization middleware is not included, this is the same as using `scope_object?`
    meta :scope?, true

    field :id, :integer
    field :email, :string
    field :name, :string

    field :company, :company
  end

  object :company do
    meta :scope_object?, true

    field :id, :integer
    field :user_id, :integer
    field :name, :string
    field :wallet, :wallet
  end

  object :wallet do
    meta :scope?, true
    meta :rule, :object_authorization

    field :total, :integer
  end
  ```

  To define custom rules for the scoping, use [has_user_access?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/3). For example:

  ```elixir
  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin],
      super_role: :admin

    @impl true
    def has_user_access?(%{role: :admin}, %User{}, _rule), do: true
    def has_user_access?(%{id: user_id}, %User{id: id}, _rule) when user_id === id, do: true
    def has_user_access?(_current_user, %User{}, _rule), do: false

    def has_user_access?(%{id: user_id}, %Wallet{user_id: id}, :object_authorization), do: user_id == id
    def has_user_access?(%{id: user_id}, %Wallet{user_id: id}, :always_block), do: false
  end
  ```

  This way different rules can be set to the same struct.
  See `Rajska.Authorization` for `rule` default settings.
  """

  alias Absinthe.{Blueprint, Phase, Type}
  alias Rajska.Introspection
  use Absinthe.Phase

  @spec run(Blueprint.t() | Phase.Error.t(), Keyword.t()) :: {:ok, map}
  def run(%Blueprint{execution: execution} = bp, _options \\ []) do
    {:ok, %{bp | execution: process(execution)}}
  end

  defp process(%{validation_errors: [], result: result} = execution), do: %{execution | result: result(result, execution.context)}
  defp process(execution), do: execution

  # Introspection
  defp result(%{emitter: %{schema_node: %{identifier: identifier}}} = result, _context)
  when identifier in [:query_type, :__schema, nil] do
    result
  end

  # Root
  defp result(%{fields: fields, emitter: %{schema_node: %{identifier: identifier}}} = result, context)
  when identifier in [:query, :mutation, :subscription] do
    %{result | fields: walk_result(fields, context)}
  end

  # Object
  defp result(%{fields: fields, emitter: %{schema_node: schema_node}, root_value: root_value} = result, context) do
    type = Introspection.get_object_type(schema_node.type)
    scope? = get_scope!(type)
    default_rule = Rajska.apply_auth_mod(context, :default_rule)
    rule = Type.meta(type, :rule) || default_rule

    case authorized?(scope?, context, root_value, rule) do
      true -> %{result | fields: walk_result(fields, context)}
      false -> Map.put(result, :errors, [error(result, context)])
    end
  end

  # List
  defp result(%{values: values} = result, context) do
    %{result | values: walk_result(values, context)}
  end

  # Leafs
  defp result(result, _context), do: result

  defp walk_result(fields, context, new_fields \\ [])

  defp walk_result([], _context, new_fields), do: Enum.reverse(new_fields)

  defp walk_result([field | fields], context, new_fields) do
    new_fields = [result(field, context) | new_fields]
    walk_result(fields, context, new_fields)
  end

  defp get_scope!(object) do
    scope? = Type.meta(object, :scope?)
    scope_object? = Type.meta(object, :scope_object?)

    case {scope?, scope_object?} do
      {nil, nil} -> true
      {nil, scope_object?} -> scope_object?
      {scope?, nil} -> scope?
      {_, _} -> raise "Error in #{inspect object.identifier}. If scope_object? is defined, then scope? must not be defined"
    end
  end

  defp authorized?(false, _context, _scoped_struct, _rule), do: true

  defp authorized?(true, context, scoped_struct, rule) do
    Rajska.apply_auth_mod(context, :context_user_authorized?, [context, scoped_struct, rule])
  end

  defp error(%{emitter: %{source_location: location, schema_node: %{type: type}}} = result, context) do
    object_type = Rajska.Introspection.get_object_type(type)
    %Phase.Error{
      phase: __MODULE__,
      message: Rajska.apply_auth_mod(context, :unauthorized_object_scope_message, [result, object_type]),
      locations: [location]
    }
  end
end
