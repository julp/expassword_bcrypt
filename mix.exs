defmodule Mix.Tasks.Compile.BcryptCmake do
  @valgrind_options ~W[-q --tool=memcheck --trace-children=yes --leak-check=full --track-origins=yes --log-file=/dev/null --error-exitcode=42]
  def run(_) do
    {result, 0} = System.cmd("cmake", [".", "-Wno-dev"], stderr_to_stdout: true, env: [{"MIX_ENV", to_string(Mix.env())}])
    Mix.shell.info(result)
    {result, 0} = System.cmd("make", ["all"], stderr_to_stdout: true)
    Mix.shell.info(result)
    if Mix.env() == :test do
      {cmd, args} = try do
        System.cmd("valgrind", [], stderr_to_stdout: true)
        {"valgrind", @valgrind_options ++ [Path.expand("src/test")]}
      rescue
        _ ->
          {Path.expand("src/test"), []}
      end
      {result, 0} = System.cmd(cmd, args, stderr_to_stdout: true)
      Mix.shell.info(result)
    end
    :ok
  end
end

defmodule ExPassword.Bcrypt.MixProject do
  use Mix.Project

  def project do
    [
      app: :expassword_bcrypt,
      version: "0.1.0",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: ~W[bcryptCmake]a ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: "https://github.com/julp/expassword_bcrypt",
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      extra_applications: ~W[crypto logger runtime_tools]a
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ~W[lib test/support]
  defp elixirc_paths(_), do: ~W[lib]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:expassword_algorithm, "~> 0.1"},
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
      #{:dialyxir, "~> 1.1", only: ~W[dev test]a, runtime: false},
    ]
  end

  defp description() do
    ~S"""
    The bcrypt "plugin" for ExPassword (as a NIF)
    """
  end

  defp package() do
    [
      files: ~W[lib src openbsd mix.exs README*],
      licenses: ~W[BSD],
      links: %{"GitHub" => "https://github.com/julp/expassword_bcrypt"},
    ]
  end
end
