defmodule Rajska.Schema do
  @moduledoc """
    Adds QueryAuthorization to Absinthe Middlewares and validate arguments passed to it
  """

  alias Absinthe.Type.Field

  alias Rajska.{ObjectAuthorization, QueryAuthorization}

  def add_query_authorization(
    [{{QueryAuthorization, :call}, config} = query_authorization | middleware],
    _field,
    authorization
  ) do
    validate_query_auth_config!(config, authorization)

    [query_authorization | middleware]
  end

  def add_query_authorization(_middleware, %Field{name: name}, _authorization) do
    raise "No permission specified for query #{name}"
  end

  def validate_query_auth_config!([permit: _, scoped: false], _authorization), do: :ok

  def validate_query_auth_config!([permit: _, scoped: {schema, _field}], _authorization), do: schema.__schema__(:source)

  def validate_query_auth_config!([permit: _, scoped: schema], _authorization), do: schema.__schema__(:source)

  def validate_query_auth_config!([permit: role], authorization) do
    case Enum.member?(authorization.not_scoped_roles(), role) do
      true -> :ok
      false -> raise "Query permitter is configured incorrectly, :scoped key must be present for role #{role}."
    end
  end

  def validate_query_auth_config!(_config, _authorization) do
    raise "Query permitter is configured incorrectly, :permit key must be present."
  end

  def add_object_authorization([{{QueryAuthorization, :call}, _} = query_authorization | middleware]) do
    [query_authorization, ObjectAuthorization] ++ middleware
  end

  def add_object_authorization(middleware), do: [ObjectAuthorization | middleware]
end
