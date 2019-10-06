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

    resolution
    |> Map.get(:context)
    |> authorized?(field_private?, scope_by, resolution.source)
    |> put_result(resolution, field)
  end

  defp field_private?(true, _source), do: true
  defp field_private?(private, source) when is_function(private), do: private.(source)
  defp field_private?(_private, _source), do: false

  defp get_scope_by_field!(_object, false), do: :ok

  defp get_scope_by_field!(object, _private) do
    case Type.meta(object, :scope_by) do
      nil -> raise "No scope_by meta defined for object returned from query #{object.identifier}"
      scope_by_field when is_atom(scope_by_field) -> scope_by_field
    end
  end

  defp authorized?(_context, false, _scope_by, _source), do: true

  defp authorized?(context, true, scope_by, source) do
    case Rajska.apply_auth_mod(context, :super_user?, [context]) do
      true -> true
      false -> Rajska.apply_auth_mod(context, :context_field_authorized?, [context, scope_by, source])
    end
  end

  defp put_result(true, resolution, _field), do: resolution

  defp put_result(false, resolution, field) do
    Resolution.put_result(resolution, {:error, "Not authorized to access field #{field}"})
  end
end
