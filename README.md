# ExpasswordBcrypt

This module add support for Bcrypt to ExPassword

## Credits

* OpenBSD for C implementation
* openwall and [Java bcrypt](https://github.com/patrickfav/bcrypt) for tests

## Prerequisites

* a C99 compiler
* CMake
* optional: Valgrind for C tests

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed by adding `expassword_bcrypt` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:expassword, "~> 0.1"},
    {:expassword_bcrypt, "~> 0.1"},
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc) and published on [HexDocs](https://hexdocs.pm). Once published, the docs can be found at [https://hexdocs.pm/expassword_bcrypt](https://hexdocs.pm/expassword_bcrypt).

## Configuration

Default values are:

```elixir
config :expassword_bcrypt,
  # the algorithmic cost, defines the number of iterations
  cost: 10
```

Of course, you can override them in your config/*.exs

In fact, you should lower these values in config/test.exs to speed up your tests.
