defmodule Rajska do
  @moduledoc """
    Functions to get the current user role from Absinthe's Resolution and validate its permissions
  """

  alias Absinthe.Resolution

  defmacro __using__(opts \\ []) do
    otp_app = Keyword.get(opts, :otp_app)
    global_config = Application.get_env(otp_app, __MODULE__, [])
    all_role = Keyword.get(opts, :all_role, global_config[:all_role]) || :all
    roles = Keyword.get(opts, :roles, global_config[:roles])
    roles_with_tier = add_tier_to_roles(roles)
    roles_names = get_role_names(roles)
    super_roles = get_super_roles(roles_with_tier)

    quote do
      @spec config() :: Keyword.t()
      def config do
        Keyword.merge(unquote(opts), [all_role: unquote(all_role), roles: unquote(roles_with_tier)])
      end

      def get_all_role, do: config()[:all_role]

      def is_super_role?(user_role) when user_role in unquote(super_roles), do: true
      def is_super_role?(_user_role), do: false

      def get_current_user(%{context: %{current_user: current_user}}), do: current_user

      def get_user_role(%{role: role}), do: role

      def get_user_role(nil), do: nil

      def get_user_role(%Resolution{} = resolution) do
        resolution
        |> get_current_user()
        |> get_user_role()
      end

      def user_role_names, do: unquote(roles_names)

      def valid_roles, do: [:all | user_role_names()]

      def not_scoped_roles, do: [:all | unquote(super_roles)]

      def is_super_user?(%Resolution{} = resolution) do
        resolution
        |> get_user_role()
        |> is_super_role?()
      end

      def is_authorized?(_resolution, unquote(all_role)), do: true

      def is_authorized?(%Resolution{} = resolution, allowed_role) do
        resolution
        |> get_user_role()
        |> is_authorized?(allowed_role)
      end

      def is_authorized?(user_role, _allowed_role) when user_role in unquote(super_roles), do: true

      def is_authorized?(user_role, allowed_role) when is_atom(allowed_role), do: user_role === allowed_role

      def unauthorized_msg, do: "unauthorized"

      defoverridable  get_current_user: 1,
                      get_user_role: 1,
                      is_authorized?: 2,
                      unauthorized_msg: 0
    end
  end

  def add_tier_to_roles(roles) when is_list(roles) do
    case Keyword.keyword?(roles) do
      true -> roles
      false -> Enum.with_index(roles, 1)
    end
  end

  def add_tier_to_roles(nil), do: raise "No roles configured in Rajska's authorization module"

  def get_role_names(roles) when is_list(roles) do
    case Keyword.keyword?(roles) do
      true -> Enum.map(roles, fn {role, _tier} -> role end)
      false -> roles
    end
  end

  def get_super_roles(roles) do
    {_, max_tier} = Enum.max_by(roles, fn {_, tier} -> tier end)

    roles
    |> Enum.filter(fn {_, tier} -> tier === max_tier end)
    |> Enum.map(fn {role, _} -> role end)
  end

  def apply_auth_mod(resolution, fnc_name, args \\ [])

  def apply_auth_mod(%{context: %{authorization: authorization}}, fnc_name, args) do
    apply(authorization, fnc_name, args)
  end

  def apply_auth_mod(_resolution, _fnc_name, _args) do
    raise "Rajska authorization module not found in Absinthe's context"
  end

  defdelegate add_authentication_middleware(middleware, field, authorization), to: Rajska.Schema
end
