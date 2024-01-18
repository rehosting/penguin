{
  description = "Penguin: Configuration Based Rehosting";

  inputs = {
    nixpkgs.url = "nixpkgs";
    panda = {
      url = "github:panda-re/panda";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    angr-targets = {
      url = "github:AndrewFasano/angr-targets/af_fixes";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, panda, angr-targets }:

    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      pyPkgs = pkgs.python3Packages;
      pandaPkg = panda.packages.x86_64-linux.default.overrideAttrs
        (final: prev: {
          patches = prev.patches ++ [
            # Add PANDA_PLUGIN_PATH
            (pkgs.fetchpatch {
              url = "https://github.com/panda-re/panda/pull/1408.patch";
              hash = "sha256-RiwYsxYOa5G7DpW5N1eB/fkA5k5mCRVhxXh4BoYwFn0=";
            })
          ];
        });
      iglooStatic = pkgs.linkFarm "igloo-static" [{
        name = "kernels";
        path = pkgs.fetchzip {
          url =
            "https://github.com/panda-re/linux_builder/releases/download/v1.8/kernels-latest.tar.gz";
          hash = "sha256-9XSFUMgsmIGgTDAwSgnWVXMVAB2a9qSSJgwt2pNvDF0=";
        };
      }];
      penguinPlugins = pkgs.fetchzip {
        url = "https://panda.re/igloo/penguin_plugins_v1.3.1.tar.gz";
        stripRoot = false;
        hash = "sha256-78YkuDlepkdabX08WfC5iBxtnM6UPMrMuDCf4Klb3WE=";
      };
      angrTargetsPkg = pyPkgs.buildPythonPackage {
        name = "angr-targets";
        src = angr-targets;
        doCheck = false;
      };
      penguin = pyPkgs.buildPythonPackage {
        name = "penguin";
        src = ./penguin;
        propagatedBuildInputs =
          (with pyPkgs; [ angr pandas pyyaml jsonschema colorama coloredlogs ]) ++ [
            (pyPkgs.guestfs.override {
              libguestfs = pkgs.libguestfs-with-appliance;
            })
          ] ++ [ pandaPkg angrTargetsPkg ];
        postPatch = ''
          substituteInPlace penguin/*.py \
            --replace '/igloo_static' '${iglooStatic}' \
            --replace '/pandata' '${./pyplugins}'
        '';
        doCheck = false;
        postInstall = ''
          (
            cd $out/lib/python*/site-packages
            mkdir resources
          )
          cp resources/config_schema.yaml $out/lib/python*/site-packages/resources/
        '';
        makeWrapperArgs = [ "--set PANDA_PLUGIN_PATH ${penguinPlugins}" ];
        meta.mainProgram = "penguin";
      };
    in { packages.x86_64-linux.default = penguin; };
}
