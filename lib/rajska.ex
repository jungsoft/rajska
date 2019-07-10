defmodule Rajska do
  @moduledoc """
  Rajska is an elixir authorization library for [Absinthe](https://github.com/absinthe-graphql/absinthe).

  It provides the following middlewares:
  - `Rajska.QueryAuthorization`
  - `Rajska.ScopeAuthorization`
  - `Rajska.ObjectAuthorization`
  - `Rajska.FieldAuthorization`

  ## Installation

  The package can be installed by adding `rajska` to your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [
      {:rajska, "~> 0.0.1"},
    ]
  end
  ```

  ## Usage

  Create your Authorization module, which will implement the `Rajska.Authorization` behaviour and contain the logic to validate user permissions and will be called by Rajska middlewares. Rajska provides some helper functions by default, such as `c:Rajska.Authorization.is_role_authorized?/2`, `c:Rajska.Authorization.has_user_access?/3` and `c:Rajska.Authorization.is_field_authorized?/3`, but you can override them with your application needs.

  ```elixir
  defmodule Authorization do
    use Rajska,
      roles: [:user, :admin]
  end
  ```

  Note: if you pass a non Keyword list to `roles`, as above, Rajska will assume your roles are in ascending order and the last one is the super role. You can override this behavior by defining your own `c:Rajska.Authorization.is_super_role?/1` function or passing a Keyword list in the format `[user: 0, admin: 1]`.

  Add your Authorization module to your `Absinthe.Schema` [context/1](https://hexdocs.pm/absinthe/Absinthe.Schema.html#c:context/1) callback and the desired middlewares to the [middleware/3](https://hexdocs.pm/absinthe/Absinthe.Middleware.html#module-the-middleware-3-callback) callback:

  ```elixir
  def context(ctx), do: Map.put(ctx, :authorization, Authorization)

  def middleware(middleware, field, %Absinthe.Type.Object{identifier: identifier})
  when identifier in [:query, :mutation, :subscription] do
    middleware
    |> Rajska.add_query_authorization(field, Authorization)
    |> Rajska.add_object_authorization()
  end

  def middleware(middleware, field, object) do
    Rajska.add_field_authorization(middleware, field, object)
  end
  ```

  You can also add all Rajska middlewares at once by calling `Rajska.Schema.add_middlewares/4`:

  ```elixir
  def context(ctx), do: Map.put(ctx, :authorization, Authorization)

  def middleware(middleware, field, object) do
    Rajska.add_middlewares(middleware, field, object, Authorization)
  end
  ```

  Since Scope Authorization middleware must be used with Query Authorization, it is automatically called when adding the former.
  """

  alias Absinthe.Resolution

  alias Rajska.Authorization

  defmacro __using__(opts \\ []) do
    all_role = Keyword.get(opts, :all_role, :all)
    roles = Keyword.get(opts, :roles)
    roles_with_tier = add_tier_to_roles!(roles)
    roles_names = get_role_names(roles)
    super_roles = get_super_roles(roles_with_tier)

    quote do
      @behaviour Authorization

      @spec config() :: Keyword.t()
      def config do
        Keyword.merge(unquote(opts), [all_role: unquote(all_role), roles: unquote(roles_with_tier)])
      end

      def get_current_user(%Resolution{context: %{current_user: current_user}}), do: current_user

      def get_user_role(%{role: role}), do: role
      def get_user_role(nil), do: nil

      def user_role_names, do: unquote(roles_names)

      def valid_roles, do: [:all | user_role_names()]

      def not_scoped_roles, do: [:all | unquote(super_roles)]

      defguard super_role?(role) when role in unquote(super_roles)

      def is_super_role?(user_role) when super_role?(user_role), do: true
      def is_super_role?(_user_role), do: false

      def is_role_authorized?(_user_role, unquote(all_role)), do: true
      def is_role_authorized?(user_role, _allowed_role) when user_role in unquote(super_roles), do: true
      def is_role_authorized?(user_role, allowed_role) when is_atom(allowed_role), do: user_role === allowed_role
      def is_role_authorized?(user_role, allowed_roles) when is_list(allowed_roles), do: user_role in allowed_roles

      def is_field_authorized?(nil, _scope_by, _source), do: false
      def is_field_authorized?(%{id: user_id}, scope_by, source), do: user_id === Map.get(source, scope_by)

      def has_user_access?(%user_struct{id: user_id} = current_user, scoped_struct, field_value) do
        is_super_user? = current_user |> get_user_role() |> is_super_role?()
        is_owner? = (user_struct === scoped_struct) && (user_id === field_value)

        is_super_user? || is_owner?
      end

      def unauthorized_msg(_resolution), do: "unauthorized"

      def is_super_user?(%Resolution{} = resolution) do
        resolution
        |> get_current_user()
        |> get_user_role()
        |> is_super_role?()
      end

      def is_resolution_authorized?(%Resolution{} = resolution, allowed_role) do
        resolution
        |> get_current_user()
        |> get_user_role()
        |> is_role_authorized?(allowed_role)
      end

      def is_resolution_field_authorized?(%Resolution{} = resolution, scope_by, source) do
        resolution
        |> get_current_user()
        |> is_field_authorized?(scope_by, source)
      end

      def has_resolution_access?(%Resolution{} = resolution, scoped_struct, field_value) do
        resolution
        |> get_current_user()
        |> has_user_access?(scoped_struct, field_value)
      end

      defoverridable Authorization
    end
  end

  @doc false
  def add_tier_to_roles!(roles) when is_list(roles) do
    case Keyword.keyword?(roles) do
      true -> roles
      false -> Enum.with_index(roles, 1)
    end
  end

  def add_tier_to_roles!(nil) do
    raise "No roles configured in Rajska's authorization module"
  end

  @doc false
  def get_role_names(roles) when is_list(roles) do
    case Keyword.keyword?(roles) do
      true -> Enum.map(roles, fn {role, _tier} -> role end)
      false -> roles
    end
  end

  @doc false
  def get_super_roles(roles) do
    {_, max_tier} = Enum.max_by(roles, fn {_, tier} -> tier end)

    roles
    |> Enum.filter(fn {_, tier} -> tier === max_tier end)
    |> Enum.map(fn {role, _} -> role end)
  end

  @doc false
  def apply_auth_mod(resolution, fnc_name, args \\ [])

  def apply_auth_mod(%Resolution{context: %{authorization: authorization}}, fnc_name, args) do
    apply(authorization, fnc_name, args)
  end

  def apply_auth_mod(_resolution, _fnc_name, _args) do
    raise "Rajska authorization module not found in Absinthe's context"
  end

  defdelegate add_middlewares(middleware, field, object, authorization), to: Rajska.Schema
  defdelegate add_query_authorization(middleware, field, authorization), to: Rajska.Schema
  defdelegate add_object_authorization(middleware), to: Rajska.Schema
  defdelegate add_field_authorization(middleware, field, object), to: Rajska.Schema
end
