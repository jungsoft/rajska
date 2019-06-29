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

  Create your authorization module, which will contain the logic to validate user permissions and will be called by Rajska middlewares. Rajska provides some helper functions by default, such as [is_authorized?/2](https://hexdocs.pm/rajska), [has_access?/3](https://hexdocs.pm/rajska) and [is_field_authorized?/3](https://hexdocs.pm/rajska), but you can override them with your application needs.

  ```elixir
  defmodule Authorization do
    use Rajska,
      otp_app: :my_app,
      roles: [:user, :admin]
  end
  ```

  Note: if you pass a non Keyword list to `roles`, as above, Rajska will assume your roles are in ascending order and the last one is the super role. You can override this behavior by defining your own `is_super_role?/1` function or passing a Keyword list in the format `[user: 0, admin: 1]`.

  Add your authorization module to your `Absinthe.Schema` [context/1](https://hexdocs.pm/absinthe/Absinthe.Schema.html#c:context/1) callback and the desired middlewares to the [middleware/3](https://hexdocs.pm/absinthe/Absinthe.Middleware.html#module-the-middleware-3-callback) callback:

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

  You can also add all Rajska middlewares at once by calling [add_middlewares/3](https://hexdocs.pm/rajska):

  ```elixir
  def context(ctx), do: Map.put(ctx, :authorization, Authorization)

  def middleware(middleware, field, object) do
    Rajska.add_middlewares(middleware, field, object, Authorization)
  end
  ```

  Since Scope Authorization middleware must be used with Query Authorization, it is automatically called when adding the former.
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

      def is_super_role?(user_role) when user_role in unquote(super_roles), do: true
      def is_super_role?(_user_role), do: false

      def is_authorized?(_resolution, unquote(all_role)), do: true

      def is_authorized?(%Resolution{} = resolution, allowed_role) do
        resolution
        |> get_user_role()
        |> is_authorized?(allowed_role)
      end

      def is_authorized?(user_role, _allowed_role) when user_role in unquote(super_roles), do: true

      def is_authorized?(user_role, allowed_role) when is_atom(allowed_role), do: user_role === allowed_role

      def is_field_authorized?(resolution, scope_by, source) do
        current_user = get_current_user(resolution)
        current_user_id = current_user && Map.get(current_user, :id)

        current_user_id === Map.get(source, scope_by)
      end

      def unauthorized_msg, do: "unauthorized"

      defoverridable  get_current_user: 1,
                      get_user_role: 1,
                      is_super_user?: 1,
                      is_super_role?: 1,
                      is_authorized?: 2,
                      is_field_authorized?: 3,
                      unauthorized_msg: 0
    end
  end

  def add_tier_to_roles(roles) when is_list(roles) do
    case Keyword.keyword?(roles) do
      true -> roles
      false -> Enum.with_index(roles, 1)
    end
  end

  def add_tier_to_roles(nil) do
    raise "No roles configured in Rajska's authorization module"
  end

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

  defdelegate add_middlewares(middleware, field, object, authorization), to: Rajska.Schema
  defdelegate add_query_authorization(middleware, field, authorization), to: Rajska.Schema
  defdelegate add_object_authorization(middleware), to: Rajska.Schema
  defdelegate add_field_authorization(middleware, field, object), to: Rajska.Schema
end
