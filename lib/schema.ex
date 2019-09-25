defmodule Rajska.Schema do
  @moduledoc """
  Concatenates Rajska middlewares with Absinthe middlewares and validates Query Authorization configuration.
  """

  alias Absinthe.Type.{
    Field,
    Middleware,
    Object
  }

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
  def add_query_authorization(
    [{{QueryAuthorization, :call}, config} = query_authorization | middleware] = _middleware,
    _field,
    authorization
  ) do
    validate_query_auth_config!(config, authorization)

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
      scoped: false | :source | {:source | module(), atom()}
    ],
    module()
  ) :: :ok | Exception.t()

  def validate_query_auth_config!([permit: _, scoped: _, rule: _] = config, authorization) do
    config
    |> Keyword.delete(:rule)
    |> validate_query_auth_config!(authorization)
  end

  def validate_query_auth_config!([permit: _, scoped: false] = _config, _authorization), do: :ok

  def validate_query_auth_config!([permit: _, scoped: :source], _authorization), do: :ok

  def validate_query_auth_config!([permit: _, scoped: {:source, _scoped_field}], _authorization), do: :ok

  def validate_query_auth_config!([permit: _, scoped: {scoped_struct, _scoped_field}], _authorization) do
    scoped_struct.__schema__(:source)
  end

  def validate_query_auth_config!([permit: _, scoped: {scoped_struct, _scoped_field, _opts}], _authorization) do
    scoped_struct.__schema__(:source)
  end

  def validate_query_auth_config!([permit: _, scoped: scoped_struct], _authorization) do
    scoped_struct.__schema__(:source)
  end

  def validate_query_auth_config!([permit: role], authorization) do
    case Enum.member?(authorization.not_scoped_roles(), role) do
      true -> :ok
      false -> raise "Query permitter is configured incorrectly, :scoped key must be present for role #{role}."
    end
  end

  def validate_query_auth_config!(_config, _authorization) do
    raise "Query permitter is configured incorrectly, :permit key must be present."
  end
end
