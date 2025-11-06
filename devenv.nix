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
    # Create lib directory and symlink Ghidra JARs
    mkdir -p lib
    
    # Link Ghidra JARs from nixpkgs installation
    GHIDRA_DIR="${pkgs.ghidra}/lib/ghidra/Ghidra"
    
    ln -sf "$GHIDRA_DIR/Framework/Generic/lib/Generic.jar" lib/Generic.jar
    ln -sf "$GHIDRA_DIR/Framework/SoftwareModeling/lib/SoftwareModeling.jar" lib/SoftwareModeling.jar
    ln -sf "$GHIDRA_DIR/Framework/Project/lib/Project.jar" lib/Project.jar
    ln -sf "$GHIDRA_DIR/Framework/Docking/lib/Docking.jar" lib/Docking.jar
    ln -sf "$GHIDRA_DIR/Features/Decompiler/lib/Decompiler.jar" lib/Decompiler.jar
    ln -sf "$GHIDRA_DIR/Framework/Utility/lib/Utility.jar" lib/Utility.jar
    ln -sf "$GHIDRA_DIR/Features/Base/lib/Base.jar" lib/Base.jar
    ln -sf "$GHIDRA_DIR/Framework/Gui/lib/Gui.jar" lib/Gui.jar
    
    echo ""
    echo "🔧 $GREET"
    echo ""
    echo "✅ Ghidra JARs linked to lib/ directory"
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
    echo "⚠️  IMPORTANT: Set GHIDRA_INSTALL_DIR in gradle.properties"
    echo "  Example: GHIDRA_INSTALL_DIR=${pkgs.ghidra}/lib/ghidra"
    echo ""
  '';

  # https://devenv.sh/pre-commit-hooks/
  # pre-commit.hooks.shellcheck.enable = true;

  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

  # See full reference at https://devenv.sh/reference/options/
}