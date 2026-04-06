import os
from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

class NvramHelper:
    @staticmethod
    def _get_default_nvram_values() -> dict[str, str]:
        nvram = {
            "console_loglevel": "7",
            "restore_defaults": "1",
            "sku_name": "",
            "wla_wlanstate": "",
            "lan_if": "br0",
            "lan_ipaddr": "192.168.0.50",
            "lan_bipaddr": "192.168.0.255",
            "lan_netmask": "255.255.255.0",
            "time_zone": "PST8PDT",
            "wan_hwaddr_def": "01:23:45:67:89:ab",
            "wan_ifname": "eth0",
            "lan_ifnames": "eth1 eth2 eth3 eth4",
            "ethConver": "1",
            "lan_proto": "dhcp",
            "wan_ipaddr": "0.0.0.0",
            "wan_netmask": "255.255.255.0",
            "wanif": "eth0",
            "time_zone_x": "0",
            "rip_multicast": "0",
            "bs_trustedip_enable": "0",
            "et0macaddr": "01:23:45:67:89:ab",
            "filter_rule_tbl": "",
            "pppoe2_schedule_config": "127:0:0:23:59",
            "schedule_config": "127:0:0:23:59",
            "access_control_mode": "0",
            "fwpt_df_count": "0",
            "static_if_status": "1",
            "www_relocation": "",
        }

        def _add_firmae_for_entries(config_dict, pattern, value, start, end):
            for index in range(start, end + 1):
                config_dict[pattern % index] = value

        _add_firmae_for_entries(
            nvram,
            "usb_info_dev%d",
            "A200396E0402FF83@1@14.4G@U@1@USB_Storage;U:;0;0@",
            0,
            101,
        )
        _add_firmae_for_entries(nvram, "wla_ap_isolate_%d", "", 1, 5)
        _add_firmae_for_entries(nvram, "wlg_ap_isolate_%d", "", 1, 5)
        _add_firmae_for_entries(nvram, "wlg_allow_access_%d", "", 1, 5)
        _add_firmae_for_entries(nvram, "%d:macaddr", "01:23:45:67:89:ab", 0, 3)
        _add_firmae_for_entries(nvram, "lan%d_ifnames", "", 1, 10)

        return nvram

    @staticmethod
    def parse_nvram_file(path: str, f) -> dict:
        file_content = f.read()
        key_val_pairs = file_content.split(b"\x00")
        results_null = {}
        results_lines = {}

        for pair in key_val_pairs[:-1]:
            try:
                key, val = pair.split(b"=", 1)
                if key.startswith(b"#"):
                    continue
                results_null[key] = val
            except ValueError:
                logger.warning(f"could not process default nvram file {path} for {pair}")
                continue

        for line in file_content.split(b"\n"):
            if line.startswith(b"#"):
                continue
            if b"=" not in line:
                continue
            key, val = line.split(b"=", 1)
            results_lines[key] = val

        if len(results_null) > 5 and len(results_null) > len(results_lines):
            return results_null
        elif len(results_lines) > 5 and len(results_lines) > len(results_null):
            return results_lines
        else:
            return {}

    @staticmethod
    def nvram_config_analysis(fs_path: str, full_path: bool = True) -> dict[str, str]:
        nvram_paths = [
            "./var/etc/nvram.default",
            "./etc/nvram.default",
            "./etc/nvram.conf",
            "./etc/nvram.deft",
            "./etc/nvram.update",
            "./etc/wlan/nvram_params",
            "./etc/system_nvram_defaults",
            "./image/mnt/nvram_ap.default",
            "./etc_ro/Wireless/RT2860AP/RT2860_default_vlan",
            "./etc_ro/Wireless/RT2860AP/RT2860_default_novlan",
            "./image/mnt/nvram_whp.default",
            "./image/mnt/nvram_rt.default",
            "./image/mnt/nvram_rpt.default",
            "./image/mnt/nvram.default",
        ]
        nvram_basenames = set([os.path.basename(x) for x in nvram_paths])

        path_nvrams = {}
        if full_path:
            for path in nvram_paths:
                abs_path = os.path.join(fs_path, path.lstrip("/"))
                if os.path.exists(abs_path):
                    with open(abs_path, "rb") as f:
                        result = NvramHelper.parse_nvram_file(path, f)
                        for k, v in result.items():
                            path_nvrams[k.decode()] = v.decode()
        else:
            for root, _, files in os.walk(fs_path):
                for file in files:
                    abs_path = os.path.join(root, file)
                    rel_path = "./" + os.path.relpath(abs_path, fs_path)

                    if rel_path in nvram_paths:
                        continue

                    if any(file == fname for fname in nvram_basenames):
                        with open(abs_path, "rb") as f:
                            result = NvramHelper.parse_nvram_file(rel_path, f)
                            for k, v in result.items():
                                path_nvrams[k.decode()] = v.decode()

        return path_nvrams
