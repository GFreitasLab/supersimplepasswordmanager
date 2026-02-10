{
  description = "Python development enviroment";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          python313
          python313Packages.cryptography
          python313Packages.typer
          python313Packages.argon2-cffi
          python313Packages.pyperclip
        ];     
      };
    };
}
