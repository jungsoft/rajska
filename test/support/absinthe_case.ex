defmodule Absinthe.Case do
  defmacro __using__(opts) do
    quote do
      use ExUnit.Case, unquote(opts)
    end
  end
end
