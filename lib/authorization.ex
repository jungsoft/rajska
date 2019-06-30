defmodule Rajska.Authorization do
  @moduledoc """
  Behaviour for an Authorization module.
  """

  alias Absinthe.Resolution

  @type current_user :: any()
  @type role :: atom()
  @type current_user_role :: role
  @type allowed_role :: role
  @type scope_by :: atom()
  @type source :: map()

  @callback get_current_user(Resolution.t) :: current_user

  @callback get_user_role(current_user) :: role

  @callback is_super_role?(role) :: boolean()

  @callback is_role_authorized?(current_user_role, allowed_role) :: boolean()

  @callback is_field_authorized?(current_user_role, scope_by, source) :: boolean()

  @callback unauthorized_msg :: String.t()

  @optional_callbacks get_current_user: 1,
                      get_user_role: 1,
                      is_super_role?: 1,
                      is_role_authorized?: 2,
                      is_field_authorized?: 3,
                      unauthorized_msg: 0
end
