defmodule Absinthe.Case do
  @moduledoc false

  defmacro __using__(opts) do
    quote do
      use ExUnit.Case, unquote(opts)
    end
  end
end
