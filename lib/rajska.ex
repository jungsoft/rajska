defmodule Rajska do
  @moduledoc """
    Functions to get the current user role from Absinthe's Resolution and validate its permissions
  """

  alias Absinthe.Resolution

  @all_role Application.get_env(__MODULE__, :all_role)

  defmacro __using__(opts \\ []) do
    otp_app = Keyword.get(opts, :otp_app)

    quote do
      @spec config() :: Keyword.t()
      def config do
        unquote(otp_app)
        |> Application.get_env(__MODULE__, [])
        |> Keyword.merge(unquote(opts))
      end

      def get_current_user(%{context: %{current_user: current_user}}), do: current_user

      def get_user_role(%{role: role}), do: role

      def get_user_role(nil), do: nil

      def get_user_role(%Resolution{} = resolution) do
        resolution
        |> get_current_user()
        |> get_user_role
      end

      defp is_authorized?(_resolution, @all_role), do: true

      defp is_authorized?(resolution, allowed_role) when is_atom(allowed_role) do
        user_role = get_user_role(resolution)

        is_super_role?(user_role) || (user_role === allowed_role)
      end

      def unauthorized_msg, do: "unauthorized"

      defoverridable  get_current_user: 1,
                      get_user_role: 1,
                      is_authorized?: 2,
                      unauthorized_msg: 0
    end
  end

  def apply_config_module(fnc_name, args \\ []) do
    Rajska
    |> Application.get_env(:configurator)
    |> apply(fnc_name, args)
  end

  def get_config(config_attr) do
    apply_config_module(:config, [config_attr])
  end

  def get_schema, do: get_config(:schema)

  def user_roles, do: get_config(:roles)

  def valid_roles, do: user_roles() ++ [@all_role]

  def get_current_user(resolution) do
    apply_config_module(:get_current_user, [resolution])
  end

  def get_user_role(resolution) do
    apply_config_module(:get_user_role, [get_current_user(resolution)])
  end

  def is_super_user?(%Resolution{} = resolution) do
    resolution
    |> get_user_role()
    |> is_super_role?()
  end

  def is_super_role?(user_role) when is_atom(user_role) do
    Enum.member?(get_super_roles(), user_role)
  end

  def get_super_roles do
    roles = user_roles()
    max_tier = Enum.max(roles, fn {_, tier} -> tier end)

    roles
    |> Enum.filter(fn {_, tier} -> tier === max_tier end)
    |> Enum.map(fn {role, _} -> role end)
  end

  def not_scoped_roles do
    get_super_roles() ++ @all_role
  end

  def unauthorized_msg, do: apply_config_module(:unauthorized_msg)
end
