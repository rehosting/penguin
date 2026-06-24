{
  description = "Penguin: configuration-based firmware rehosting framework";

  nixConfig = {
    extra-substituters = [ "https://rehosting-tools.cachix.org" ];
    extra-trusted-public-keys = [
      "rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0="
    ];
  };

  # Pinned to the same nixpkgs commit as penguin-tools so the two flakes share a
  # store closure (and Cachix hits).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b6067cc0127d4db9c26c79e4de0513e58d0c40c9";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          lib = pkgs.lib;

          # ---- Penguin core Python environment ----------------------------
          # The post-prune dependency set (angr/symex and the 13 unused
          # packages are gone). Firmware-extraction Python backends (binwalk
          # fork, unblob, jefferson, ubi_reader, yaffshiv, vmlinux-to-elf,
          # python-magic) are intentionally NOT here -- they belong to the
          # extraction stack, which is sourced from fw2tar's closure (deferred).
          #
          # python3 (nixpkgs default) rather than the Dockerfile's 3.10; bump
          # down only if a dep refuses to build.
          py = pkgs.python3;

          # The three core deps not packaged in nixpkgs.
          pydantic-partial = py.pkgs.callPackage ./nix/pydantic-partial.nix { };
          junit-xml = py.pkgs.callPackage ./nix/junit-xml.nix { };
          dwarffi = py.pkgs.callPackage ./nix/dwarffi.nix { };

          pythonEnv = py.withPackages (ps: [
            ps.coloredlogs
            ps.ipython
            ps.levenshtein
            ps.jinja2
            ps.lxml
            ps.lz4
            ps.pydantic
            ps.pyelftools
            ps.pyyaml
            ps.pyvis
            ps.jsonschema
            ps.click
            ps.art
            ps.setuptools
            ps.sqlalchemy
            ps.jc
            ps.ujson
            ps.cxxfilt
            ps.pdoc
            ps.ratarmountcore
            pydantic-partial
            junit-xml
            dwarffi
          ]);
        in
        {
          inherit pythonEnv;
          default = pythonEnv;
        }
      );
    };
}
