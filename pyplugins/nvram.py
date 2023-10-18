from pandare import PyPlugin
from os.path import join
import tarfile

console_path = "console.log"

class NVRAM(PyPlugin):
    pass
    # Nothing to do at runtime. Until we drop in HyperNVRam

# But we analyze console output after the fact
def propose_configs(config, result_dir, quiet=False):
    # Based off FirmAE's approach https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/inferDefault.py#L69
    nvram_gets = set()

    with open(join(result_dir, console_path), "rb") as f:
        # XXX this is broken
        for line in f.readlines():
            if line.startswith(b"nvram_get_buf:") and b"Unable to open" not in line and b"=" not in line:
                # 'nvam_get_buf: foo' should return 'foo'
                data = line.split(":")[1].strip()
                nvram_gets.add(data)

    if len(nvram_gets):
        print("Nvram gets:")
        for k in nvram_gets:
            print(k)

        # Try to find the nvram file in the base image
        fs_tar_path = config['base']['fs']
        # Open the tarfile
        tar = tarfile.open(fs_tar_path, "r")
        # Iterate through members
        for member in tar.getmembers():
            # For each file in the archive, check if it contains at least half of the nvram_gets
            # If so, we assume it's the nvram file
            # Read file
            if not member.isfile():
                continue

            match_count = 0
            data = tar.extractfile(member.name).read()

            for k in nvram_gets:
                if k in data:
                    match_count += 1

            if match_count > len(nvram_gets)//4:
                print("Potential nvram file:", member.name)

    return []