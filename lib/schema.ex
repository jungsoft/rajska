defmodule Rajska.Schema do
  @moduledoc """
  Concatenates Rajska middlewares with Absinthe middlewares and validates Query Authorization configuration.
  """

  alias Absinthe.Middleware
  alias Absinthe.Type.{Field, Object}
  alias Absinthe.Phase.Schema.Introspection

  alias Rajska.{
    FieldAuthorization,
    ObjectAuthorization,
    QueryAuthorization
  }

  @spec add_query_authorization(
    [Middleware.spec(), ...],
    Field.t(),
    module()
  ) :: [Middleware.spec(), ...]
  def add_query_authorization(middleware, %{definition: Introspection}, _authorizaton),
    do: middleware
  def add_query_authorization(
    [{{QueryAuthorization, :call}, config} = query_authorization | middleware] = _middleware,
    %Field{name: query_name},
    authorization
  ) do
    validate_query_auth_config!(config, authorization, query_name)

    [query_authorization | middleware]
  end

  def add_query_authorization(_middleware, %Field{name: name}, _authorization) do
    raise "No permission specified for query #{name}"
  end

  @spec add_object_authorization([Middleware.spec(), ...]) :: [Middleware.spec(), ...]
  def add_object_authorization([{{QueryAuthorization, :call}, _} = query_authorization | middleware]) do
    [query_authorization, ObjectAuthorization] ++ middleware
  end

  def add_object_authorization(middleware), do: [ObjectAuthorization | middleware]

  @spec add_field_authorization(
    [Middleware.spec(), ...],
    Field.t(),
    Object.t()
  ) :: [Middleware.spec(), ...]
  def add_field_authorization(middleware, %Field{identifier: field}, object) do
    [{{FieldAuthorization, :call}, object: object, field: field} | middleware]
  end

  @spec validate_query_auth_config!(
    [
      permit: atom(),
      scope: false | module(),
      args: %{} | [] | atom(),
      optional: false | true,
      rule: atom()
    ],
    module(),
    String.t()
  ) :: :ok | Exception.t()

  def validate_query_auth_config!(config, authorization, query_name) do
    permit = Keyword.get(config, :permit)
    scope = Keyword.get(config, :scope)
    args = Keyword.get(config, :args, :id)
    rule = Keyword.get(config, :rule, :default_rule)
    optional = Keyword.get(config, :optional, false)

    try do
      validate_presence!(permit, :permit)
      validate_boolean!(optional, :optional)
      validate_atom!(rule, :rule)

      validate_scope!(scope, permit, authorization)
      validate_args!(args)
    rescue
      e in RuntimeError -> reraise "Query #{query_name} is configured incorrectly, #{e.message}", __STACKTRACE__
    end
  end

  defp validate_presence!(nil, option), do: raise "#{inspect(option)} option must be present."
  defp validate_presence!(_value, _option), do: :ok

  defp validate_boolean!(value, _option) when is_boolean(value), do: :ok
  defp validate_boolean!(_value, option), do: raise "#{inspect(option)} option must be a boolean."

  defp validate_atom!(value, _option) when is_atom(value), do: :ok
  defp validate_atom!(_value, option), do: raise "#{inspect(option)} option must be an atom."

  defp validate_scope!(nil, role, authorization) do
    unless Enum.member?(authorization.not_scoped_roles(), role),
      do: raise ":scope option must be present for role #{inspect(role)}."
  end

  defp validate_scope!(false, _role, _authorization), do: :ok

  defp validate_scope!(scope, _role, _authorization) when is_atom(scope) do
    struct!(scope)
  rescue
    UndefinedFunctionError -> reraise ":scope option #{inspect(scope)} is not a struct.", __STACKTRACE__
  end

  defp validate_args!(args) when is_map(args) do
    Enum.each(args, fn
      {field, value} when is_atom(field) and is_atom(value) -> :ok
      {field, values} when is_atom(field) and is_list(values)  -> validate_list_of_atoms!(values)
      field_value -> raise "the following args option is invalid: #{inspect(field_value)}. Since the provided args is a map, you should provide an atom key and an atom or list of atoms value."
    end)
  end

  defp validate_args!(args) when is_list(args), do: validate_list_of_atoms!(args)

  defp validate_args!(args) when is_atom(args), do: :ok

  defp validate_args!(args), do: raise "the following args option is invalid: #{inspect(args)}"

  defp validate_list_of_atoms!(args) do
    Enum.each(args, fn
      arg when is_atom(arg) -> :ok
      arg -> raise "the following args option is invalid: #{inspect(args)}. Expected a list of atoms, but found #{inspect(arg)}"
    end)
  end
end
