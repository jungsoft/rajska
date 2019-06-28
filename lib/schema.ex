defmodule Rajska.Schema do
  @moduledoc """
    Adds QueryPermitter to Absinthe Middlewares and validate arguments passed to it
  """

  alias Absinthe.Type.Field

  alias Rajska.QueryPermitter

  def add_authentication_middleware([{{QueryPermitter, :call}, config} = query_permitter | middleware], _field) do
    validate_query_permitter!(config)

    [query_permitter] ++ middleware
  end

  def add_authentication_middleware(_middleware, %Field{name: name}) do
    raise "No permission specified for query #{name}"
  end

  defp validate_query_permitter!([permit: _, scoped: false]), do: :ok

  defp validate_query_permitter!([permit: _, scoped: {schema, _field}]), do: schema.__schema__(:source)

  defp validate_query_permitter!([permit: _, scoped: schema]), do: schema.__schema__(:source)

  defp validate_query_permitter!([permit: role]) do
    case Enum.member?(Rajska.not_scoped_roles(), role) do
      true -> :ok
      false -> raise "Query permitter is configured incorrectly, :scoped key must be present for role #{role}."
    end
  end

  defp validate_query_permitter!(_), do: raise "Query permitter is configured incorrectly, :permit key must be present."
end
