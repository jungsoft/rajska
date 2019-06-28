defmodule Rajska.Schema do
  @moduledoc """
    Adds QueryPermitter to Absinthe Middlewares and validate arguments passed to it
  """

  alias Absinthe.Type.Field

  alias Rajska.QueryPermitter

  def add_authentication_middleware(
    [{{QueryPermitter, :call}, config} = query_permitter | middleware],
    _field,
    authorization
  ) do
    validate_query_permitter!(config, authorization)

    [query_permitter] ++ middleware
  end

  def add_authentication_middleware(_middleware, %Field{name: name}, _authorization) do
    raise "No permission specified for query #{name}"
  end

  defp validate_query_permitter!([permit: _, scoped: false], _authorization), do: :ok

  defp validate_query_permitter!([permit: _, scoped: {schema, _field}], _authorization), do: schema.__schema__(:source)

  defp validate_query_permitter!([permit: _, scoped: schema], _authorization), do: schema.__schema__(:source)

  defp validate_query_permitter!([permit: role], authorization) do
    case Enum.member?(authorization.not_scoped_roles(), role) do
      true -> :ok
      false -> raise "Query permitter is configured incorrectly, :scoped key must be present for role #{role}."
    end
  end

  defp validate_query_permitter!(_config, _authorization) do
    raise "Query permitter is configured incorrectly, :permit key must be present."
  end
end
