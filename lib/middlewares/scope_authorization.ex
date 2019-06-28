defmodule Rajska.ScopeAuthorization do
  @moduledoc """
    Middleware to block access to private projects.
  """

  @behaviour Absinthe.Middleware

  alias Absinthe.{Resolution, Type}

  def call(%{state: :resolved} = resolution, _config), do: resolution

  def call(resolution, [_ | [scoped: false]]), do: resolution

  def call(resolution, [{:permit, permission} | scoped_config]) do
    case Enum.member?(Rajska.not_scoped_roles(), permission) do
      true -> resolution
      false -> scope_user(resolution, scoped_config)
    end
  end

  def scope_user(%{source: source} = resolution, scoped: :source) do
    apply_scope_authorization(resolution, source.id, source.__struct__)
  end

  def scope_user(%{arguments: args} = resolution, scoped: {schema, field}) do
    apply_scope_authorization(resolution, Map.get(args, field), schema)
  end

  def scope_user(%{arguments: args} = resolution, scoped: schema) do
    apply_scope_authorization(resolution, Map.get(args, :id), schema)
  end

  def scope_user(
    %{
      definition: %{
        name: name,
        schema_node: %{type: %Type.List{of_type: _}}
      }
    },
    _scoped_config
  ) do
    raise "Error in query #{name}: Scope Authorization can't be used with a list query object type"
  end

  def scope_user(%{definition: %{name: name}}, _) do
    raise "Error in query #{name}: no scoped argument found in middleware Scope Authorization"
  end

  def apply_scope_authorization(%{definition: %{name: name}}, nil, _schema) do
    raise "Error in query #{name}: no argument found in middleware Scope Authorization"
  end

  def apply_scope_authorization(resolution, id, schema) do
    :validate_scoped_query
    |> Rajska.apply_config_mod([schema, id, resolution])
    |> update_result(resolution)
  end

  defp update_result(true, resolution), do: resolution

  defp update_result(
    false,
    %{definition: %{schema_node: %{type: object_type}}} = resolution
  ) do
    put_error(resolution, "Not authorized to access this #{replace_underscore(object_type)}")
  end

  defp update_result({:error, msg}, resolution), do: put_error(resolution, msg)

  defp put_error(resolution, message), do: Resolution.put_result(resolution, {:error, message})

  defp replace_underscore(string) when is_binary(string), do: String.replace(string, "_", " ")
end
