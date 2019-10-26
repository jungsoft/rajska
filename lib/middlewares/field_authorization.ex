defmodule Rajska.FieldAuthorization do
  @moduledoc """
  Absinthe middleware to ensure field permissions.

  Authorizes Absinthe's object [field](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#field/4) according to the result of the `c:Rajska.Authorization.field_authorized?/3` function, which receives the user role, the meta `scope_by` atom defined in the object schema and the `source` object that is resolving the field.

  ## Usage

  [Create your Authorization module and add it and FieldAuthorization to your Absinthe.Schema](https://hexdocs.pm/rajska/Rajska.html#module-usage). Then add the meta `scope_by` to an object and meta `private` to your sensitive fields:

  ```elixir
  object :user do
    meta :scope_by, :id

    field :name, :string
    field :is_email_public, :boolean

    field :phone, :string, meta: [private: true]
    field :email, :string, meta: [private: & !&1.is_email_public]
  end
  ```

  As seen in the example above, a function can also be passed as value to the meta `:private` key, in order to check if a field is private dynamically, depending of the value of another field.
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.{
    Resolution,
    Type
  }

  def call(resolution, [object: %Type.Object{fields: fields} = object, field: field]) do
    field_private? = fields[field] |> Type.meta(:private) |> field_private?(resolution.source)
    scope_by = get_scope_by_field!(object, field_private?)

    default_rule = Rajska.apply_auth_mod(resolution.context, :default_rule)
    rule = fields[field] |> Type.meta(:rule) || default_rule

    resolution
    |> Map.get(:context)
    |> authorized?(field_private?, scope_by, resolution, rule)
    |> put_result(resolution, field)
  end

  defp field_private?(true, _source), do: true
  defp field_private?(private, source) when is_function(private), do: private.(source)
  defp field_private?(_private, _source), do: false

  defp get_scope_by_field!(_object, false), do: :ok

  defp get_scope_by_field!(object, _private) do
    general_scope_by = Type.meta(object, :scope_by)
    field_scope_by = Type.meta(object, :scope_field_by)

    case {general_scope_by, field_scope_by} do
      {nil, nil} -> raise "No meta scope_by or scope_field_by defined for object #{object.identifier}"
      {nil, field_scope_by} -> field_scope_by
      {general_scope_by, nil} -> general_scope_by
      {_, _} -> raise "Error in #{object.identifier}: scope_by should only be defined alone. If scope_field_by is defined, then scope_by must not be defined"
    end
  end

  defp authorized?(_context, false, _scope_by, _source, _rule), do: true

  defp authorized?(context, true, scope_by, %{source: %scope{} = source}, rule) do
    field_value = Map.get(source, scope_by)

    Rajska.apply_auth_mod(context, :has_context_access?, [context, scope, {scope_by, field_value}, rule])
  end

  defp authorized?(_context, true, _scope_by, %{source: source, definition: definition}, _rule) do
    raise "Expected a Struct for source object in field #{inspect(definition.name)}, got #{inspect(source)}"
  end

  defp put_result(true, resolution, _field), do: resolution

  defp put_result(false, resolution, field) do
    Resolution.put_result(resolution, {:error, "Not authorized to access field #{field}"})
  end
end
