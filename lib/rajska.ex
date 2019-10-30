defmodule Rajska do
  @moduledoc """
  Rajska is an elixir authorization library for [Absinthe](https://github.com/absinthe-graphql/absinthe).

  It provides the following middlewares:
  - `Rajska.QueryAuthorization`
  - `Rajska.QueryScopeAuthorization`
  - `Rajska.ObjectAuthorization`
  - `Rajska.ObjectScopeAuthorization`
  - `Rajska.FieldAuthorization`

  ## Installation

  The package can be installed by adding `rajska` to your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [
      {:rajska, "~> 0.8.1"},
    ]
  end
  ```

  ## Usage

  Create your Authorization module, which will implement the `Rajska.Authorization` behaviour and contain the logic to validate user permissions and will be called by Rajska middlewares. Rajska provides some helper functions by default, such as `c:Rajska.Authorization.role_authorized?/2`, `c:Rajska.Authorization.has_user_access?/4` and `c:Rajska.Authorization.field_authorized?/3`, but you can override them with your application needs.

  ```elixir
  defmodule Authorization do
    use Rajska,
      valid_roles: [:user, :admin]
  end
  ```

  Available options and their default values:

  ```elixir
  valid_roles: [:admin],
  super_role: :admin,
  default_rule: :default
  ```

  Add your Authorization module to your `Absinthe.Schema` [context/1](https://hexdocs.pm/absinthe/Absinthe.Schema.html#c:context/1) callback and the desired middlewares to the [middleware/3](https://hexdocs.pm/absinthe/Absinthe.Middleware.html#module-the-middleware-3-callback) callback:

  ```elixir
  def context(ctx), do: Map.put(ctx, :authorization, Authorization)

  def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
  when identifier in [:query, :mutation] do
    middleware
    |> Rajska.add_query_authorization(field, Authorization)
    |> Rajska.add_object_authorization()
  end

  def middleware(middleware, field, object) do
    Rajska.add_field_authorization(middleware, field, object)
  end
  ```

  Since Scope Authorization middleware must be used with Query Authorization, it is automatically called when adding the former.
  """

  alias Rajska.Authorization

  defmacro __using__(opts \\ []) do
    super_role = Keyword.get(opts, :super_role, :admin)
    valid_roles = Keyword.get(opts, :valid_roles, [super_role])
    default_rule =  Keyword.get(opts, :default_rule, :default)

    quote do
      @behaviour Authorization

      @spec config() :: Keyword.t()
      def config do
        Keyword.merge(unquote(opts), [
          valid_roles: unquote(valid_roles),
          super_role: unquote(super_role),
          default_rule: unquote(default_rule)
        ])
      end

      def get_current_user(%{current_user: current_user}), do: current_user

      def get_user_role(%{role: role}), do: role
      def get_user_role(nil), do: nil

      def default_rule, do: unquote(default_rule)

      def valid_roles, do: [:all | unquote(valid_roles)]

      def not_scoped_roles, do: [:all, unquote(super_role)]

      defguard is_super_role(role) when role === unquote(super_role)

      def super_role?(role) when is_super_role(role), do: true
      def super_role?(_user_role), do: false

      def role_authorized?(_user_role, :all), do: true
      def role_authorized?(role, _allowed_role) when is_super_role(role), do: true
      def role_authorized?(user_role, allowed_role) when is_atom(allowed_role), do: user_role === allowed_role
      def role_authorized?(user_role, allowed_roles) when is_list(allowed_roles), do: user_role in allowed_roles

      def has_user_access?(%user_struct{id: user_id} = current_user, scope, {field, field_value}, unquote(default_rule)) do
        super_user? = current_user |> get_user_role() |> super_role?()
        owner? =
          (user_struct === scope)
          && (field === :id)
          && (user_id === field_value)

        super_user? || owner?
      end

      def unauthorized_msg(_resolution), do: "unauthorized"

      def super_user?(context) do
        context
        |> get_current_user()
        |> get_user_role()
        |> super_role?()
      end

      def context_authorized?(context, allowed_role) do
        context
        |> get_current_user()
        |> get_user_role()
        |> role_authorized?(allowed_role)
      end

      def has_context_access?(context, scope, {scope_field, field_value}, rule) do
        context
        |> get_current_user()
        |> has_user_access?(scope, {scope_field, field_value}, rule)
      end

      defoverridable Authorization
    end
  end

  @doc false
  def apply_auth_mod(context, fnc_name, args \\ [])

  def apply_auth_mod(%{authorization: authorization}, fnc_name, args) do
    apply(authorization, fnc_name, args)
  end

  def apply_auth_mod(_context, _fnc_name, _args) do
    raise "Rajska authorization module not found in Absinthe's context"
  end

  defdelegate add_query_authorization(middleware, field, authorization), to: Rajska.Schema
  defdelegate add_object_authorization(middleware), to: Rajska.Schema
  defdelegate add_field_authorization(middleware, field, object), to: Rajska.Schema
end
