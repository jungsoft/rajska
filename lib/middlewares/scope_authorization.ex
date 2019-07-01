defmodule Rajska.ScopeAuthorization do
  @moduledoc """
  Absinthe middleware to perform query scoping.

  ## Usage

  [Create your Authorization module and add it and QueryAuthorization to your Absinthe.Schema](https://hexdocs.pm/rajska/Rajska.html#module-usage). Since Scope Authorization middleware must be used with Query Authorization, it is automatically called when adding the former. Then set the scoped module and argument field:

  ```elixir
  mutation do
    field :create_user, :user do
      arg :params, non_null(:user_params)

      middleware Rajska.QueryAuthorization, permit: :all
      resolve &AccountsResolver.create_user/2
    end

    field :update_user, :user do
      arg :id, non_null(:integer)
      arg :params, non_null(:user_params)

      middleware Rajska.QueryAuthorization, [permit: :user, scoped: User] # same as {User, :id}
      resolve &AccountsResolver.update_user/2
    end

    field :delete_user, :user do
      arg :id, non_null(:integer)

      middleware Rajska.QueryAuthorization, permit: :admin
      resolve &AccountsResolver.delete_user/2
    end
  end
  ```

  In the above example, `:all` and `:admin` permissions don't require the `:scoped` keyword, as defined in the `c:Rajska.Authorization.not_scoped_roles/0` function, but you can modify this behavior by overriding it.

  Valid values for the `:scoped` keyword are:
  - `false`: disables scoping
  - `User`: a module that will be passed to `c:Rajska.Authorization.has_user_access?/3`. It must implement a `Rajska.Authorization` behaviour and a `__schema__(:source)` function (used to check if the module is valid in `Rajska.Schema.validate_query_auth_config!/2`)
  - `{User, :id}`: where `:id` is the query argument that will also be passed to `c:Rajska.Authorization.has_user_access?/3`
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.{Resolution, Type}

  def call(%Resolution{state: :resolved} = resolution, _config), do: resolution

  def call(resolution, [_ | [scoped: false]]), do: resolution

  def call(resolution, [{:permit, permission} | scoped_config]) do
    not_scoped_roles = Rajska.apply_auth_mod(resolution, :not_scoped_roles)

    case Enum.member?(not_scoped_roles, permission) do
      true -> resolution
      false -> scope_user!(resolution, scoped_config)
    end
  end

  def scope_user!(%Resolution{source: source} = resolution, scoped: :source) do
    apply_scope_authorization(resolution, source.id, source.__struct__)
  end

  def scope_user!(%Resolution{source: source} = resolution, scoped: {:source, scoped_field}) do
    apply_scope_authorization(resolution, Map.get(source, scoped_field), source.__struct__)
  end

  def scope_user!(%Resolution{arguments: args} = resolution, scoped: {scoped_struct, scoped_field}) do
    apply_scope_authorization(resolution, Map.get(args, scoped_field), scoped_struct)
  end

  def scope_user!(%Resolution{arguments: args} = resolution, scoped: scoped_struct) do
    apply_scope_authorization(resolution, Map.get(args, :id), scoped_struct)
  end

  def scope_user!(
    %Resolution{
      definition: %{
        name: name,
        schema_node: %{type: %Type.List{of_type: _}}
      }
    },
    _scoped_config
  ) do
    raise "Error in query #{name}: Scope Authorization can't be used with a list query object type"
  end

  def scope_user!(%Resolution{definition: %{name: name}}, _scoped_config) do
    raise "Error in query #{name}: no scoped argument found in middleware Scope Authorization"
  end

  def apply_scope_authorization(%Resolution{definition: %{name: name}}, nil, _scoped_struct) do
    raise "Error in query #{name}: no argument found in middleware Scope Authorization"
  end

  def apply_scope_authorization(resolution, field_value, scoped_struct) do
    resolution
    |> Rajska.apply_auth_mod(:has_resolution_access?, [resolution, scoped_struct, field_value])
    |> update_result(resolution)
  end

  defp update_result(true, resolution), do: resolution

  defp update_result(
    false,
    %Resolution{definition: %{schema_node: %{type: object_type}}} = resolution
  ) do
    put_error(resolution, "Not authorized to access this #{replace_underscore(object_type)}")
  end

  defp update_result({:error, msg}, resolution), do: put_error(resolution, msg)

  defp put_error(resolution, message), do: Resolution.put_result(resolution, {:error, message})

  defp replace_underscore(string) when is_binary(string), do: String.replace(string, "_", " ")

  defp replace_underscore(atom) when is_atom(atom) do
    atom
    |> Atom.to_string()
    |> replace_underscore()
  end
end
