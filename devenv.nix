{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/basics/
  env.GREET = "Ghidra MCP Plugin Development Environment";
  env.GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";

  # https://devenv.sh/packages/
  packages = with pkgs; [
    git
    gradle
    jdk17
    ghidra
  ];

  # https://devenv.sh/languages/
  languages.java.enable = true;
  languages.java.jdk.package = pkgs.jdk17;

  # https://devenv.sh/scripts/
  scripts.build.exec = ''
    echo "Building Ghidra MCP Plugin..."
    gradle clean build
  '';

  scripts.compile.exec = ''
    echo "Compiling Ghidra MCP Plugin..."
    gradle classes
  '';

  scripts.test.exec = ''
    echo "Running tests..."
    gradle test
  '';

  scripts.clean.exec = ''
    echo "Cleaning build artifacts..."
    gradle clean
  '';

  enterShell = ''
    echo ""
    echo "🔧 $GREET"
    echo ""
    echo "✅ GHIDRA_INSTALL_DIR is set to: $GHIDRA_INSTALL_DIR"
    echo "   Gradle will use JARs directly from Ghidra installation"
    echo ""
    echo "Available commands:"
    echo "  build    - Build the complete plugin package"
    echo "  compile  - Compile the plugin (faster, no packaging)"
    echo "  test     - Run tests"
    echo "  clean    - Clean build artifacts"
    echo ""
    echo "Java version:"
    java -version
    echo ""
    echo "Gradle version:"
    gradle -version
    echo ""
    echo "Ghidra version:"
    echo "  ${pkgs.ghidra.version}"
    echo ""
  '';

  # https://devenv.sh/pre-commit-hooks/
  # pre-commit.hooks.shellcheck.enable = true;

  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

  # See full reference at https://devenv.sh/reference/options/
}