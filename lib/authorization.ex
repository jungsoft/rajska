defmodule Rajska.Authorization do
  @moduledoc """
  Behaviour of an Authorization module.
  """

  alias Absinthe.Resolution

  @type current_user :: any()
  @type role :: atom()
  @type current_user_role :: role

  @callback get_current_user(context :: map()) :: current_user

  @callback get_user_role(current_user) :: role

  @callback not_scoped_roles() :: list(role)

  @callback role_authorized?(current_user_role, allowed_role :: role) :: boolean()

  @callback has_user_access?(current_user, scoped_struct :: struct(), rule :: any()) :: boolean()

  @callback unauthorized_message(resolution :: Resolution.t()) :: String.t()

  @optional_callbacks get_current_user: 1,
                      get_user_role: 1,
                      not_scoped_roles: 0,
                      role_authorized?: 2,
                      has_user_access?: 3,
                      unauthorized_message: 1
end
