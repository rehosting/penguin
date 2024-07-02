import os
import tarfile
from copy import deepcopy
from .common import yaml
from .penguin_manager import run_config
from .penguin_prep import prepare_run

# Given a base config, run it with some dynamnic analysises to profile the target shell


def _build_bb_profile(config, outdir, bb_path):
    # Run target with an init=/igloo/bb_profile
    # Create a file inside the guest with a
    # #![bb_path] \n echo $testvar echo $othertest

    # Make a unique run_dir for each bb_path
    thisoutdir = os.path.join(*[outdir, "profiles", bb_path.replace("/", "_")])
    os.makedirs(thisoutdir)

    newconfig = deepcopy(config)
    if "files" not in newconfig:
        newconfig["files"] = []

    payload = f"#!{bb_path}\n\n"

    payload += "\n".join(
        [
            "echo $testvarone",
            "echo $testtwo",
            # "export unused=$testthree",
            "eval $testfour",
            # "echo $((testfive + 1))",
            # "read -r unused <<< $testsix",
            "/igloo/utils/busybox halt -f",
        ]
    )

    newconfig["files"].append(
        {
            "type": "file",
            "mode": 0o755,
            "path": "/igloo/init_test",  # We use inconsistent names for our test vars to get various lengths
            "contents": payload,
        }
    )

    newconfig["pyplugins"] = ["/pandata/findcmp"]

    # We want to replace init=anything with init=/igloo/init_test, but we might not have an append at all
    if "append" not in newconfig:
        newconfig["append"] = []

    newconfig["append"].append("init=/igloo/init_test")
    newconfig["append"].append("firmadyne.reboot=0")  # Allow guest to shut down!

    # Write config to thisoutdir
    newconfigpath = os.path.join(thisoutdir, "config.yaml")
    with open(newconfigpath, "w") as f:
        yaml.dump(newconfig, f)

    # Gimme Qcow plz
    prepare_run(newconfigpath, thisoutdir)

    # Now let's run this bad boi with findcall and co!
    run_config(thisoutdir)  # YOLO?


def make_bb_profile(config_path, outdir):
    config = yaml.load(open(config_path), Loader=yaml.FullLoader)
    fs_path = config["core"]["fs"]  # tar archive

    bbs = set()
    with tarfile.open(fs_path) as fs:
        for member in fs:
            if member.name.startswith("./igloo"):
                continue

            if (
                member.issym()
                and os.path.basename(member.linkname) == "busybox"
                and os.path.basename(member.name) in ["ash", "sh", "bash", "dash"]
            ):
                bbs.add(member.name.replace("./", "/"))  # XXX This gets redundant!

            elif os.path.basename(member.name) in ["sh", "bash"]:
                bbs.add(member.path.replace("./", "/"))

    print("Found busyboxes:")
    print(bbs)

    for bb in bbs:
        _build_bb_profile(config, outdir, bb)


if __name__ == "__main__":
    from sys import argv

    if len(argv) != 3:
        print("Usage: python3 penguin_bb_profile.py <config> <outdir>")
        exit(1)
    make_bb_profile(argv[1], argv[2])
