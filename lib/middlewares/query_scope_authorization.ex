defmodule Rajska.QueryScopeAuthorization do
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

      middleware Rajska.QueryAuthorization, [permit: :user, scope: User] # same as [permit: :user, scope: User, args: :id]
      resolve &AccountsResolver.update_user/2
    end

    field :delete_user, :user do
      arg :id, non_null(:integer)

      middleware Rajska.QueryAuthorization, permit: :admin
      resolve &AccountsResolver.delete_user/2
    end

    field :invite_user, :user do
      arg :email, non_null(:string)

      middleware Rajska.QueryAuthorization, [permit: :user, scope: User, rule: :invitation]
      resolve &AccountsResolver.invite_user/2
    end
  end
  ```

  In the above example, `:all` and `:admin` permissions don't require the `:scope` keyword, as defined in the `c:Rajska.Authorization.not_scoped_roles/0` function, but you can modify this behavior by overriding it.

  ## Options

  All the following options are sent to `c:Rajska.Authorization.has_user_access?/4`:

    * `:scope`
      - `false`: disables scoping
      - `User`: a module that will be passed to `c:Rajska.Authorization.has_user_access?/4`. It must implement a `Rajska.Authorization` behaviour and a `__schema__(:source)` function (used to check if the module is valid in `Rajska.Schema.validate_query_auth_config!/2`)
    * `:args`
      - `%{user_id: [:params, :id]}`: where `user_id` is the scoped field and `id` is an argument nested inside the `params` argument.
      - `:id`: this is the same as `%{id: :id}`, where `:id` is both the query argument and the scoped field that will be passed to `c:Rajska.Authorization.has_user_access?/4`
      - `[:code, :user_group_id]`: this is the same as `%{code: :code, user_group_id: :user_group_id}`, where `code` and `user_group_id` are both query arguments and scoped fields.
    * `:optional` (optional) - when set to true the arguments are optional, so if no argument is provided, the query will be authorized. Defaults to false.
    * `:rule` (optional) - allows the same struct to have different rules. See `Rajska.Authorization` for `rule` default settings.
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.Resolution

  alias Rajska.Introspection

  def call(%Resolution{state: :resolved} = resolution, _config), do: resolution

  def call(resolution, [_ | [scope: false]]), do: resolution

  def call(resolution, [{:permit, permission} | scope_config]) do
    not_scoped_roles = Rajska.apply_auth_mod(resolution.context, :not_scoped_roles)

    case Enum.member?(not_scoped_roles, permission) do
      true -> resolution
      false -> scope_user!(resolution, scope_config)
    end
  end

  def scope_user!(%{context: context} = resolution, config) do
    default_rule = Rajska.apply_auth_mod(context, :default_rule)
    rule = Keyword.get(config, :rule, default_rule)
    scope = Keyword.get(config, :scope)
    arg_fields = config |> Keyword.get(:args, :id) |> arg_fields_to_map()
    optional = Keyword.get(config, :optional, false)
    arguments_source = get_arguments_source!(resolution, scope)

    arg_fields
    |> Enum.all?(& apply_scope_authorization(resolution, scope, arguments_source, &1, rule, optional))
    |> update_result(resolution)
  end

  defp arg_fields_to_map(field) when is_atom(field), do: Map.new([{field, field}])
  defp arg_fields_to_map(fields) when is_list(fields), do: fields |> Enum.map(& {&1, &1}) |> Map.new()
  defp arg_fields_to_map(field) when is_map(field), do: field

  defp get_arguments_source!(%Resolution{definition: %{name: name}}, nil) do
    raise "Error in query #{name}: no scope argument found in middleware Scope Authorization"
  end

  defp get_arguments_source!(%Resolution{source: source}, :source), do: source

  defp get_arguments_source!(%Resolution{arguments: args}, _scope), do: args

  def apply_scope_authorization(
    %Resolution{definition: definition, context: context},
    scope,
    arguments_source,
    {scope_field, arg_field},
    rule,
    optional
  ) do
    case get_scope_field_value(arguments_source, arg_field) do
      nil -> optional || raise "Error in query #{definition.name}: no argument #{inspect arg_field} found in #{inspect arguments_source}"
      field_value -> has_context_access?(context, scope, {scope_field, field_value}, rule)
    end
  end

  defp get_scope_field_value(arguments_source, fields) when is_list(fields), do: get_in(arguments_source, fields)
  defp get_scope_field_value(arguments_source, field) when is_atom(field), do: Map.get(arguments_source, field)

  defp has_context_access?(context, scope, {scope_field, field_value}, rule) do
    Rajska.apply_auth_mod(context, :has_context_access?, [context, scope, {scope_field, field_value}, rule])
  end

  defp update_result(true, resolution), do: resolution

  defp update_result(
    false,
    %Resolution{definition: %{schema_node: %{type: object_type}}} = resolution
  ) do
    object_type = Introspection.get_object_type(object_type)
    put_error(resolution, "Not authorized to access this #{replace_underscore(object_type)}")
  end

  defp put_error(resolution, message), do: Resolution.put_result(resolution, {:error, message})

  defp replace_underscore(string) when is_binary(string), do: String.replace(string, "_", " ")

  defp replace_underscore(atom) when is_atom(atom) do
    atom
    |> Atom.to_string()
    |> replace_underscore()
  end
end
