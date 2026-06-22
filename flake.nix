{
  description = "nfsdiag client-side NFS diagnostic tool";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "nfsdiag";
          version = "0.11.0";
          src = self;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libtirpc ];
          makeFlags = [ "PREFIX=${placeholder "out"}" ];
          installTargets = [ "install" ];
          meta = with pkgs.lib; {
            description = "Client-side NFS diagnostic tool";
            homepage = "https://www.nfsdiag.org";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.default}/bin/nfsdiag";
        };
      });
    };
}
