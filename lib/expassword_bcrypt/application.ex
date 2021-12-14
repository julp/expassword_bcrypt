defmodule ExPassword.Bcrypt.Application do
  use Application

  @impl Application
  def start(_type, _args) do
    ExPassword.Registry.register_algorithm(ExPassword.Bcrypt)

    Supervisor.start_link([], strategy: :one_for_one)
  end
end
