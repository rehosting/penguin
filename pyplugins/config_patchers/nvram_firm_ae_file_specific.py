import os
from penguin.static_plugin import ConfigPatcherPlugin
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class NvramFirmAEFileSpecific(ConfigPatcherPlugin):
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "nvram.05_firmae_file_specific"

    def generate(self, patches: dict) -> dict | None:
        result = {}

        for key, queries in self.FIRMAE_TARGETS.items():
            if not os.path.isfile(os.path.join(self.extracted_fs, key[1:])):
                continue

            try:
                with open(os.path.join(self.extracted_fs, key[1:]), "rb") as f:
                    content = f.read()
                    for query, _ in queries:
                        if query.encode() in content:
                            result[key] = query
            except Exception as e:
                logger.error(f"Failed to read {key} for nvram key check: {e}")

        if len(result):
            return {'nvram': result}
