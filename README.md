# Rajska

Rajska is an elixir authorization library for [Absinthe](https://github.com/absinthe-graphql/absinthe).

It provides the following middlewares:

- FieldAuthorization: authorizes Absinthe's object [field](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#field/4)

- ObjectAuthorization: authorizes Absinthe's [object](https://hexdocs.pm/absinthe/Absinthe.Schema.Notation.html#object/3)

- ScopeAuthorization: scopes Absinthe's queries

- QueryPermitter: validates if logged user can perform queries and mutations

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
