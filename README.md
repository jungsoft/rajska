# Rajska

[![Coverage Status](https://coveralls.io/repos/github/jungsoft/rajska/badge.svg?branch=master)](https://coveralls.io/github/jungsoft/rajska?branch=master)

Rajska is an elixir authorization library for [Absinthe](https://github.com/absinthe-graphql/absinthe).

It provides the following middlewares:

- [Query Authorization](#query-authorization)
- [Query Scope Authorization](#query-scope-authorization)
- [Object Authorization](#object-authorization)
- [Object Scope Authorization](#object-scope-authorization)
- [Field Authorization](#field-authorization)
- [Rate Limiter](#rate-limiter)

Documentation can be found at [https://hexdocs.pm/rajska/](https://hexdocs.pm/rajska).

## Installation

The package can be installed by adding `rajska` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:rajska, "~> 1.0.0"},
  ]
end
```

## Usage

Create your Authorization module, which will implement the [Rajska Authorization](https://hexdocs.pm/rajska/Rajska.Authorization.html) behaviour and contain the logic to validate user permissions and will be called by Rajska middlewares. Rajska provides some helper functions by default, such as [role_authorized?/2](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:role_authorized?/2) and [has_user_access?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/3), but you can override them with your application needs.

```elixir
defmodule Authorization do
  use Rajska,
    valid_roles: [:user, :admin],
    super_role: :admin,
    default_rule: :default
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

#### Usage:

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

    middleware Rajska.QueryAuthorization, [permit: [:user, :manager], scope: false]
    resolve &AccountsResolver.update_user/2
  end

  field :invite_user, :user do
    arg :email, non_null(:string)

    middleware Rajska.QueryAuthorization, permit: :admin
    resolve &AccountsResolver.invite_user/2
  end
end
```

Query authorization will call [role_authorized?/2](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:role_authorized?/2) to check if the [user](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:get_current_user/1) [role](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:get_user_role/1) is authorized to perform the query.

### Query Scope Authorization

Provides scoping to Absinthe's queries, allowing for more complex authorization rules. It is used together with [Query Authorization](#query-authorization).

```elixir
mutation do
  field :create_user, :user do
    arg :params, non_null(:user_params)

    # all does not require scoping, since it means anyone can execute this query, even without being logged in.
    middleware Rajska.QueryAuthorization, permit: :all
    resolve &AccountsResolver.create_user/2
  end

  field :update_user, :user do
    arg :id, non_null(:integer)
    arg :params, non_null(:user_params)

    middleware Rajska.QueryAuthorization, [permit: :user, scope: User] # same as [permit: :user, scope: User, args: :id]
    resolve &AccountsResolver.update_user/2
  end

  field :delete_user, :user do
    arg :user_id, non_null(:integer)

    # Providing a map for args is useful to map query argument to struct field.
    middleware Rajska.QueryAuthorization, [permit: [:user, :manager], scope: User, args: %{id: :user_id}]
    resolve &AccountsResolver.delete_user/2
  end

  input_object :user_params do
    field :id, non_null(:integer)
  end

  field :accept_user, :user do
    arg :params, non_null(:user_params)

    middleware Rajska.QueryAuthorization, [
      permit: :user,
      scope: User,
      args: %{id: [:params, :id]},
      rule: :accept_user
    ]
    resolve &AccountsResolver.invite_user/2
  end
end
```

In the above example, `:all` and `:admin` (`super_role`) permissions don't require the `:scope` keyword, but you can modify this behavior by overriding the [not_scoped_roles/0](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:not_scoped_roles/0) function.

There are also extra options for this middleware, supporting the definition of custom rules, access of nested parameters and allowing optional parameters. All possibilities are listed below:

#### Options

All the following options are sent to [has_user_access?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/3):

* `:scope`
  - `false`: disables scoping
  - `User`: a module that will be passed to `c:Rajska.Authorization.has_user_access?/3`. It must define a struct.
* `:args`
  - `%{user_id: [:params, :id]}`: where `user_id` is the scoped field and `id` is an argument nested inside the `params` argument.
  - `:id`: this is the same as `%{id: :id}`, where `:id` is both the query argument and the scoped field that will be passed to [has_user_access?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/3)
  - `[:code, :user_group_id]`: this is the same as `%{code: :code, user_group_id: :user_group_id}`, where `code` and `user_group_id` are both query arguments and scoped fields.
* `:optional` (optional) - when set to true the arguments are optional, so if no argument is provided, the query will be authorized. Defaults to false.
* `:rule` (optional) - allows the same struct to have different rules. See `Rajska.Authorization` for `rule` default settings.

### Object Authorization

Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the permission defined in each object meta `authorize`.

#### Usage:

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

Authorizes all Absinthe's [objects](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3) requested in a query by checking the underlying struct.

#### Usage:

[Create your Authorization module and add it and ObjectScopeAuthorization to your Absinthe pipeline](#usage). Then set the scope of an object:

```elixir
object :user do
  # Turn on both Object and Field scoping, but if the FieldAuthorization middleware is not included, this is the same as using `scope_object?`
  meta :scope?, true

  field :id, :integer
  field :email, :string
  field :name, :string

  field :company, :company
end

object :company do
  meta :scope_object?, true

  field :id, :integer
  field :user_id, :integer
  field :name, :string
  field :wallet, :wallet
end

object :wallet do
  meta :scope?, true
  meta :rule, :object_authorization

  field :total, :integer
end
```

To define custom rules for the scoping, use [has_user_access?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/3). For example:

```elixir
defmodule Authorization do
  use Rajska,
    valid_roles: [:user, :admin],
    super_role: :admin

  @impl true
  def has_user_access?(%{role: :admin}, %User{}, _rule), do: true
  def has_user_access?(%{id: user_id}, %User{id: id}, _rule) when user_id === id, do: true
  def has_user_access?(_current_user, %User{}, _rule), do: false

  def has_user_access?(%{id: user_id}, %Wallet{user_id: id}, :object_authorization), do: user_id == id
end
```

This way different rules can be set to the same struct.

### Field Authorization

Authorizes Absinthe's object [field](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#field/4) according to the result of the [has_user_access?/3](https://hexdocs.pm/rajska/Rajska.Authorization.html#c:has_user_access?/3) function, which receives the user role, the `source` object that is resolving the field and the field rule.

#### Usage:

[Create your Authorization module and add it and FieldAuthorization to your Absinthe.Schema](#usage).

```elixir
object :user do
  # Turn on both Object and Field scoping, but if the ObjectScope Phase is not included, this is the same as using `scope_field?`
  meta :scope?, true

  field :name, :string
  field :is_email_public, :boolean

  field :phone, :string, meta: [private: true]
  field :email, :string, meta: [private: & !&1.is_email_public]

  # Can also use custom rules for each field
  field :always_private, :string, meta: [private: true, rule: :private]
end

object :field_scope_user do
  meta :scope_field?, true

  field :name, :string
  field :phone, :string, meta: [private: true]
end
```

As seen in the example above, a function can also be passed as value to the meta `:private` key, in order to check if a field is private dynamically, depending of the value of another field.

### Rate Limiter

Rate limiter absinthe middleware. Uses [Hammer](https://github.com/ExHammer/hammer).

#### Usage

First configure Hammer, following its documentation. For example:

```elixir
config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 4,
                              cleanup_interval_ms: 60_000 * 10]}
```

Add your middleware to the query that should be limited:

```elixir
field :default_config, :string do
  middleware Rajska.RateLimiter
  resolve fn _, _ -> {:ok, "ok"} end
end
```

You can also configure it and use multiple rules for limiting in one query:

```elixir
field :login_user, :session do
  arg :email, non_null(:string)
  arg :password, non_null(:string)

  middleware Rajska.RateLimiter, limit: 10 # Using the default identifier (user IP)
  middleware Rajska.RateLimiter, keys: :email, limit: 5 # Using the value provided in the email arg
  resolve &AccountsResolver.login_user/2
end
```

The allowed configuration are:

* `scale_ms`: The timespan for the maximum number of actions. Defaults to 60_000.
* `limit`: The maximum number of actions in the specified timespan. Defaults to 10.
* `id`: An atom or string to be used as the bucket identifier. Note that this will always be the same, so by using this the limit will be global instead of by user.
* `keys`: An atom or a list of atoms to get a query argument as identifier. Use a list when the argument is nested.
* `error_msg`: The error message to be displayed when rate limit exceeds. Defaults to `"Too many requests"`.

Note that when neither `id` or `keys` is provided, the default is to use the user's IP. For that, the default behaviour is to use
`c:Rajska.Authorization.get_ip/1` to fetch the IP from the absinthe context. That means you need to manually insert the user's IP in the
absinthe context before using it as an identifier. See the [absinthe docs](https://hexdocs.pm/absinthe/context-and-authentication.html#content)
for more information.

## Related Projects

[Crudry](https://github.com/jungsoft/crudry) is an elixir library for DRYing CRUD of Phoenix Contexts and Absinthe Resolvers.

## License

MIT License.

See [LICENSE](./LICENSE) for more information.
