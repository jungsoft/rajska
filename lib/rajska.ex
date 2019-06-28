defmodule Rajska do
  @moduledoc """
    Functions to get the current user role from Absinthe's Resolution and validate its permissions
  """

  alias Absinthe.Resolution

  defmacro __using__(opts \\ []) do
    all_role = Keyword.get(opts, :all_role, :all)
    roles = Keyword.get(opts, :roles, Application.get_env(__MODULE__, :roles))
    roles_with_tier = add_tier_to_roles(roles)

    quote do
      @spec config() :: Keyword.t()
      def config do
        Keyword.merge(unquote(opts), [all_role: unquote(all_role), roles: unquote(roles_with_tier)])
      end

      def get_all_role, do: config()[:all_role]

      def get_current_user(%{context: %{current_user: current_user}}), do: current_user

      def get_user_role(%{role: role}), do: role

      def get_user_role(nil), do: nil

      def get_user_role(%Resolution{} = resolution) do
        resolution
        |> get_current_user()
        |> get_user_role
      end

      def is_authorized?(_resolution, unquote(all_role)), do: true

      def is_authorized?(resolution, allowed_role) when is_atom(allowed_role) do
        user_role = get_user_role(resolution)

        Rajska.is_super_role?(user_role) || (user_role === allowed_role)
      end

      def unauthorized_msg, do: "unauthorized"

      defoverridable  get_current_user: 1,
                      get_user_role: 1,
                      is_authorized?: 2,
                      unauthorized_msg: 0
    end
  end

  def get_app_name do
    {:ok, otp_app} = :application.get_application(__MODULE__)
    otp_app
  end

  def add_tier_to_roles(roles) do
    case Keyword.keyword?(roles) do
      true -> roles
      false -> Enum.with_index(roles, 1)
    end
  end

  def apply_config_mod(fnc_name, args \\ []) do
    __MODULE__
    |> Application.get_env(:configurator)
    |> apply(fnc_name, args)
  end

  def get_config(key) do
    :config
    |> apply_config_mod([])
    |> Keyword.get(key)
  end

  def get_schema, do: get_config(:schema)

  def user_roles, do: get_config(:roles)

  def user_role_names do
    Enum.map(user_roles(), fn {role, _} -> role end)
  end

  def valid_roles, do: user_role_names() ++ [:all]

  def get_current_user(resolution) do
    apply_config_mod(:get_current_user, [resolution])
  end

  def get_user_role(resolution) do
    apply_config_mod(:get_user_role, [get_current_user(resolution)])
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
    {_, max_tier} = Enum.max_by(roles, fn {_, tier} -> tier end)

    roles
    |> Enum.filter(fn {_, tier} -> tier === max_tier end)
    |> Enum.map(fn {role, _} -> role end)
  end

  def not_scoped_roles do
    get_super_roles() ++ :all
  end

  def unauthorized_msg, do: apply_config_mod(:unauthorized_msg)

  defdelegate add_authentication_middleware(middleware, field), to: Rajska.Schema
end
