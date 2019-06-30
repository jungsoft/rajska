# Rajska

Rajska is an elixir authorization library for [Absinthe](https://github.com/absinthe-graphql/absinthe).

It provides the following middlewares:

- [Query Authorization](#query-authorization)
- [Scope Authorization](#scope-authorization)
- [Object Authorization](#object-authorization)
- [Field Authorization](#field-authorization)

Documentation can be found at [https://hexdocs.pm/rajska/](https://hexdocs.pm/rajska).

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
      roles: [:user, :admin]
  end
```

Note: if you pass a non Keyword list to `roles`, as above, Rajska will assume your roles are in ascending order and the last one is the super role. You can override this behavior by defining your own `is_super_role?/1` function or define your `roles` as a Keyword list in the format `[user: 0, admin: 1]`.

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

Middlewares usage can be found below.

## Middlewares

### Query Authorization

Ensures Absinthe's queries can only be accessed by determined users.

Usage:

```elixir
  mutation do
    field :create_user, :user do
      arg :params, non_null(:user_params)

      middleware Rajska.QueryAuthorization, permit: :all
      resolve &AccountsResolver.create_user/2
    end

    field :update_user, :user do
      arg :id, non_null(:integer)
      arg :params, non_null(:user_params)

      middleware Rajska.QueryAuthorization, [permit: :user, scoped: User] # same as {User, :id}
      resolve &AccountsResolver.update_user/2
    end

    field :delete_user, :user do
      arg :id, non_null(:integer)

      middleware Rajska.QueryAuthorization, permit: :admin
      resolve &AccountsResolver.delete_user/2
    end
  end
```

Query authorization will call [is_authorized?/2](https://hexdocs.pm/rajska) to validate if the resolution is authorized to perform the requested query.

### Scope Authorization

Provides scoping to Absinthe's queries, as seen above in [Query Authorization](#query-authorization).

In the above example, `:all` and `:admin` permissions don't require the `:scoped` keyword, as defined in the [not_scoped_roles/0](https://hexdocs.pm/rajska) function, but you can modify this behavior by overriding it.

Valid values for the `:scoped` keyword are:

- `false`: disables scoping
- `User`: will be passed to [has_access?/3](https://hexdocs.pm/rajska) and can be any module that implements a `__schema__(:source)` function (used to check if the module is valid in [validate_query_auth_config!/2](https://hexdocs.pm/rajska))
- `{User, :id}`: where `:id` is the query argument that will also be passed to [has_access?/3](https://hexdocs.pm/rajska)

### Object Authorization

Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the permission defined in each object meta `authorize`.

Usage:

```elixir
  object :wallet_balance do
    meta :authorize, :admin

    field :total, :integer
  end

  object :company do
    meta :authorize, :user

    field :name, :string

    field :wallet_balance, :wallet_balance
  end

  object :user do
    meta :authorize, :all

    field :email, :string

    field :company, :company
  end
```

With the permissions above, a query like the following would only be allowed by an admin user:

```graphql
 {
  userQuery {
    name
    email
    company {
      name
      walletBalance { total }
    }
  }
}
```

Object Authorization middleware runs after Query Authorization middleware (if added) and before the query is resolved by recursively checking the requested objects permissions in the [is_authorized?/2](https://hexdocs.pm/rajska) function (which is also used by Query Authorization). It can be overridden by your own implementation.

### Field Authorization

Authorizes Absinthe's object [field](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#field/4) according to the result of the [is_field_authorized?/3](https://hexdocs.pm/rajska) function, which receives the [Absinthe resolution](https://hexdocs.pm/absinthe/Absinthe.Resolution.html), the meta `scope_by` atom defined in the object schema and the `source` object that is resolving the field.

Usage:

```elixir
  object :user do
    meta :scope_by, :id

    field :name, :string
    field :is_email_public, :boolean

    field :phone, :string, meta: [private: true]
    field :email, :string, meta: [private: & !&1.is_email_public]
  end
```

As seen in the example above, a function can also be passed as value to the meta `:private` key, in order to check if a field is private dynamically, depending of the value of other object field.

## Related Projects

[Crudry](https://github.com/gabrielpra1/crudry) is an elixir library for DRYing CRUD of Phoenix Contexts and Absinthe Resolvers.

## License

MIT License.

See [LICENSE](./LICENSE) for more information.
