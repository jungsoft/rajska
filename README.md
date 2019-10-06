# Rajska

[![Coverage Status](https://coveralls.io/repos/github/rschef/rajska/badge.svg?branch=master)](https://coveralls.io/github/rschef/rajska?branch=master)

Rajska is an elixir authorization library for [Absinthe](https://github.com/absinthe-graphql/absinthe).

It provides the following middlewares:

- [Query Authorization](#query-authorization)
- [Query Scope Authorization](#query-scope-authorization)
- [Object Authorization](#object-authorization)
- [Object Scope Authorization](#object-scope-authorization)
- [Field Authorization](#field-authorization)

Documentation can be found at [https://hexdocs.pm/rajska/](https://hexdocs.pm/rajska).

## Installation

The package can be installed by adding `rajska` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:rajska, "~> 0.4.1"},
  ]
end
```

## Usage

Create your Authorization module, which will implement the [Rajska Authorization](https://hexdocs.pm/rajska/Rajska.Authorization.html) behaviour and contain the logic to validate user permissions and will be called by Rajska middlewares. Rajska provides some helper functions by default, such as [role_authorized?/2](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:role_authorized?/2), [has_user_access?/4](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/4) and [field_authorized?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:field_authorized?/3), but you can override them with your application needs.

```elixir
  defmodule Authorization do
    use Rajska,
      roles: [:user, :admin]
  end
```

Add your [Authorization](https://hexdocs.pm/rajska/Rajska.Authorization.html) module to your `Absinthe.Schema` [context/1](https://hexdocs.pm/absinthe/Absinthe.Schema.html#c:context/1) callback and the desired middlewares to the [middleware/3](https://hexdocs.pm/absinthe/Absinthe.Middleware.html#module-the-middleware-3-callback) callback:

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

The only exception is [Object Scope Authorization](#object-scope-authorization), which isn't a middleware, but an [Absinthe Phase](https://hexdocs.pm/absinthe/Absinthe.Phase.html). To use it, add it to your pipeline after the resolution:

```elixir
# router.ex
alias Absinthe.Phase.Document.Execution.Resolution
alias Absinthe.Pipeline
alias Rajska.ObjectScopeAuthorization

forward "/graphql", Absinthe.Plug,
  schema: MyProjectWeb.Schema,
  socket: MyProjectWeb.UserSocket,
  pipeline: {__MODULE__, :pipeline} # Add this line

def pipeline(config, pipeline_opts) do
  config
  |> Map.fetch!(:schema_mod)
  |> Pipeline.for_document(pipeline_opts)
  |> Pipeline.insert_after(Resolution, ObjectScopeAuthorization)
end
```

Since Query Scope Authorization middleware must be used with Query Authorization, it is automatically called when adding the former.

Middlewares usage can be found below.

## Middlewares

### Query Authorization

Ensures Absinthe's queries can only be accessed by determined users.

Usage:

[Create your Authorization module and add it and QueryAuthorization to your Absinthe.Schema](#usage). Then set the permitted role to access a query or mutation:

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

Query authorization will call [role_authorized?/2](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:role_authorized?/2) to check if the [user](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:get_current_user/1) [role](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:get_user_role/1) is authorized to perform the query.

### Query Scope Authorization

Provides scoping to Absinthe's queries, as seen above in [Query Authorization](#query-authorization).

In the above example, `:all` and `:admin` permissions don't require the `:scoped` keyword, as defined in the [not_scoped_roles/0](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:not_scoped_roles/0) function, but you can modify this behavior by overriding it.

Valid values for the `:scoped` keyword are:

- `false`: disables scoping
- `User`: a module that will be passed to [has_user_access?/4](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/4). It must implement a [Authorization behaviour](https://hexdocs.pm/rajska/Rajska.Authorization.html) and a `__schema__(:source)` function (used to check if the module is valid in [validate_query_auth_config!/2](https://hexdocs.pm/rajska/Rajska.Schema.html#validate_query_auth_config!/2))
- `{User, :id}`: where `:id` is the query argument that will also be passed to [has_user_access?/4](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/4)
- `{User, [:params, :id]}`: where `id` is the query argument as above, but it's not defined directly as an `arg` for the query. Instead, it's nested inside the `params` argument.
- `{User, :user_group_id, :optional}`: where `user_group_id` (it could also be a nested argument) is an optional argument for the query. If it's present, the scoping will be applied, otherwise no scoping is applied.

### Object Authorization

Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the permission defined in each object meta `authorize`.

Usage:

[Create your Authorization module and add it and ObjectAuthorization to your Absinthe.Schema](#usage). Then set the permitted role to access an object:

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

Object Authorization middleware runs after Query Authorization middleware (if added) and before the query is resolved by recursively checking the requested objects permissions in the [role_authorized?/2](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:role_authorized?/2) function (which is also used by Query Authorization). It can be overridden by your own implementation.

### Object Scope Authorization

Absinthe Phase to perform object scoping.

Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the value of the field defined in each object meta `scope`.

Usage:

[Create your Authorization module and add it and ObjectScopeAuthorization to your Absinthe pipeline](#usage). Then set the scope of an object:

```elixir
object :user do
  meta :scope, User # Same as meta :scope, {User, :id}

  field :id, :integer
  field :email, :string
  field :name, :string

  field :company, :company
end

object :company do
  meta :scope, {Company, :user_id}

  field :id, :integer
  field :user_id, :integer
  field :name, :string
  field :wallet, :wallet
end

object :wallet do
  meta :scope, Wallet

  field :total, :integer
end
```

To define custom rules for the scoping, use [has_user_access?/4](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/4). For example:

```elixir
defmodule Authorization do
  use Rajska,
    roles: [:user, :admin]

  @impl true
  def has_user_access?(%{role: :admin}, User, _id, _rule), do: true
  def has_user_access?(%{id: user_id}, User, id, _rule) when user_id === id, do: true
  def has_user_access?(_current_user, User, _id, _rule), do: false
end
```

Keep in mind that the `field_value` provided to `has_user_access?/4` can be `nil`. This case can be handled as you wish.
For example, to not raise any authorization errors and just return `nil`:

```elixir
defmodule Authorization do
  use Rajska,
    roles: [:user, :admin]

  @impl true
  def has_user_access?(_user, _, nil), do: true

  def has_user_access?(%{role: :admin}, User, _id, _rule), do: true
  def has_user_access?(%{id: user_id}, User, id, _rule) when user_id === id, do: true
  def has_user_access?(_current_user, User, _id, _rule), do: false
end
```

### Field Authorization

Authorizes Absinthe's object [field](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#field/4) according to the result of the [field_authorized?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:field_authorized?/3) function, which receives the user role, the meta `scope_by` atom defined in the object schema and the `source` object that is resolving the field.

Usage:

[Create your Authorization module and add it and FieldAuthorization to your Absinthe.Schema](#usage). Then add the meta `scope_by` to an object and meta `private` to your sensitive fields:

```elixir
  object :user do
    meta :scope_by, :id

    field :name, :string
    field :is_email_public, :boolean

    field :phone, :string, meta: [private: true]
    field :email, :string, meta: [private: & !&1.is_email_public]
  end
```

As seen in the example above, a function can also be passed as value to the meta `:private` key, in order to check if a field is private dynamically, depending of the value of another field.

## Related Projects

[Crudry](https://github.com/gabrielpra1/crudry) is an elixir library for DRYing CRUD of Phoenix Contexts and Absinthe Resolvers.

## License

MIT License.

See [LICENSE](./LICENSE) for more information.
