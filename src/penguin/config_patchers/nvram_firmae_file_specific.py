from . import PatchGenerator
import os
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class NvramFirmAEFileSpecific(PatchGenerator):
    """
    Apply FW-specific nvram patches based on presence of hardcoded strings in files from FirmAE.
    """
    FIRMAE_TARGETS: dict[str, list[tuple[str, str]]] = {
        "./sbin/rc": [("ipv6_6to4_lan_ip", "2002:7f00:0001::")],
        "./lib/libacos_shared.so": [("time_zone_x", "0")],
        "./sbin/acos_service": [("rip_enable", "0")],
        "./usr/sbin/httpd": [
            ("rip_multicast", "0"),
            ("bs_trustedip_enable", "0"),
            ("filter_rule_tbl", ""),
        ],
    }

    def __init__(self, fs_path: str) -> None:
        self.fs_path = fs_path
        self.patch_name = "nvram.05_firmae_file_specific"

    def generate(self, patches: dict) -> dict | None:
        result = {}

        # For each key in static_targets, check if the query is in the file
        # TODO: Should we be operating on an archive to better handle symlinks?
        for key, queries in self.FIRMAE_TARGETS.items():
            if not os.path.isfile(os.path.join(self.fs_path, key[1:])):
                continue

            try:
                with open(os.path.join(self.fs_path, key[1:]), "rb") as f:
                    for query, _ in queries:
                        # Check if query is in file
                        if query.encode() in f.read():
                            result[key] = query
            except Exception as e:
                # Not sure what kind of errors we could encounter here, missing files? perms?
                logger.error(f"Failed to read {key} for nvram key check: {e}")

        if len(result):
            return {'nvram': result}
