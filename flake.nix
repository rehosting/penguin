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
      inherit (pkgs) linkFarm runCommand fetchzip;
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
      iglooStatic = linkFarm "igloo-static" [
        {
          name = "kernels";
          path = fetchzip {
            url =
              "https://github.com/panda-re/linux_builder/releases/download/v1.8/kernels-latest.tar.gz";
            hash = "sha256-9XSFUMgsmIGgTDAwSgnWVXMVAB2a9qSSJgwt2pNvDF0=";
          };
        }
        {
          name = "console";
          path = runCommand "console-links" {
            src = fetchzip {
              url =
                "https://github.com/panda-re/console/releases/download/release_389e179dde938633ff6a44144fe1e03570497479/console-latest.tar.gz";
              hash = "sha256-RS+nyq5yx7gZTI75G+Vc5Bba464gONAx3C7WAGRcdF0=";
            };
          } ''
            mkdir $out
            ln -s $src/console-arm-linux-musleabi $out/console.armel
            ln -s $src/console-mipsel-linux-musl $out/console.mipsel
            ln -s $src/console-mipseb-linux-musl $out/console.mipseb
            ln -s $src/console-mips64eb-linux-musl $out/console.mips64eb
          '';
        }
        {
          name = "libnvram";
          path = fetchzip {
            url =
              "https://github.com/panda-re/libnvram/releases/download/release_7cf4b464578bbe9df2ef0adf2eae6d577fd8f788/libnvram-latest.tar.gz";
            hash = "sha256-tD+mylSj6k5P7HlYX8KJk/GtCa45RT4SFponsEyFXuM=";
          };
        }
        {
          name = "utils.bin";
          path = runCommand "utils.bin" {
            utils = fetchzip {
              url = "https://panda.re/secret/utils4.tar.gz";
              hash = "sha256-8Q8lbUdvGN8m9wWc4CQHKvd4ePsDB16kligUU1Nf7/Q=";
            };
            busybox = fetchzip {
              url =
                "https://github.com/panda-re/busybox/releases/download/release_25c906fe05766f7fc4765f4e6e719b717cc2d9b7/busybox-latest.tar.gz";
              hash = "sha256-j+qu4HFDzp0uBPvkeay1hshMi2w2/WZcuJ+A52AIPPo=";
            };
          } ''
            mkdir $out

            echo Linking utils
            for file in $utils/*; do
              ln -s $file $out/$(basename $file)
            done

            echo Linking busybox
            for file in $busybox/busybox.*-linux*; do
              ln -s $file $out/$(basename ''${file%-linux-*})
            done
            mv $out/busybox.arm{,el}
          '';
        }
        {
          name = "vpn";
          path = fetchzip {
            url = "https://panda.re/igloo/vpn.tar.gz";
            hash = "sha256-ih1xK7dpJ0p8AU0C3K49/WWC36Ws4AQYkTorCU3EqBI=";
          };
        }
      ];
      penguinPlugins = fetchzip {
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
          (with pyPkgs; [ angr pandas pyyaml jsonschema colorama coloredlogs ])
          ++ [
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
      unittest = runCommand "unittest" {
        buildInputs = [ penguin ] ++ (with pkgs; [ fakeroot genext2fs ]);
        src = ./.;
      } ''
        unpackPhase
        cd *-source
        patchShebangs penguin/scripts/makeImage.sh unittest/*.sh
        substituteInPlace unittest/test.sh --replace \
          'docker run --rm -it -v "$(pwd)":/tests pandare/igloo:penguin' \
          "${
            pkgs.lib.getExe pkgs.bubblewrap
          } --dev-bind / / --bind $PWD/penguin /pkg --bind $PWD/unittest /tests --bind ${iglooStatic} /igloo_static --bind $PWD/utils /igloo_static/utils.source --" \
          --replace '> log.txt || (tail log.txt && exit 1)' '|| exit 1'
        substituteInPlace unittest/_in_container_run.sh --replace 'ln -s /tests/qcows "/tmp/qcows"' ""
        cd unittest
        ./test.sh
        :> $out
      '';
    in {
      packages.x86_64-linux = {
        default = penguin;
        inherit penguin;
      };
      checks.x86_64-linux = { inherit unittest; };
    };
}
