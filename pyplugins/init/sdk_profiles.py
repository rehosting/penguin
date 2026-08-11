"""
SDK profiles: fingerprint common silicon SDKs from static analyses and emit the
config bundle each SDK tends to need.

A *profile* is a catalog YAML (``profiles/<name>.yaml``) with a fingerprint and
one or more fidelity-tiered bundles. :class:`SdkFinder` scores every profile's
fingerprint against analyses that already run (InterfaceFinder, ClusterCollector,
LibrarySymbols) -- it is the consumer those analyses were missing. Each profile
then has a patch class (e.g. :class:`BroadcomHndProfile`) that emits a bundle as
``sdk.<name>``, ENABLED when the fingerprint corroborates (>=
``enable_if.min_signals``) and DISABLED (a search candidate, not a baked-in
default) otherwise.

Fidelity tiers (``bundles:`` in the catalog YAML) let one SDK offer two rungs of
the same emulation, both keyed off the single shared fingerprint:

* ``libinject`` (Tier 0, shipping) -- shim the SDK's nvram/switch symbols at the
  library layer and answer from the config. Cheap; the firmware's own flash code
  never runs.
* ``mtd`` (Tier 1, reserved) -- model the actual ``/dev/mtdN`` nvram partition
  (via the native MTD device in ``hyperfile/mtd.py``) with a backing image whose
  bytes are the SDK's real flash blob, so the firmware's own nvram library parses
  it (exercising CRC/commit/erase/reflash). Built per-SDK once its flash format
  is reversed; emitted as a separate disabled ``sdk.<name>.mtd`` candidate the
  search can promote over the Tier-0 patch.

Slice 1 ships two profiles (``broadcom_hnd``, ``qualcomm_qsdk``) with explicit
Tier-0 patch classes, mirroring the Slice-0 per-SDK alias classes; a generic
catalog-driven emitter and the Tier-1 MTD classes are deferred.
"""

from pathlib import Path

import yaml

from penguin import getColoredLogger
from penguin.init_plugin import InitContext, InitPlugin, cached_analysis

logger = getColoredLogger("penguin.init.sdk_profiles")

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"


def load_profiles(profile_dir: Path = PROFILE_DIR) -> dict[str, dict]:
    """Load every ``profiles/*.yaml`` as ``{name: profile_dict}``."""
    profiles: dict[str, dict] = {}
    if not profile_dir.is_dir():
        return profiles
    for path in sorted(profile_dir.glob("*.yaml")):
        try:
            with open(path) as f:
                prof = yaml.safe_load(f) or {}
        except Exception as e:  # noqa: BLE001 - a broken catalog entry shouldn't kill init
            logger.warning(f"Failed to load SDK profile {path}: {e}")
            continue
        name = prof.get("name")
        if name:
            profiles[name] = prof
    return profiles


def _signal_fires(signal: dict, evidence: dict[str, set]) -> bool:
    """Whether one fingerprint entry matches the target's static evidence.

    ``evidence`` maps a signal kind (``interface``/``executable``/``file``/
    ``symbol``) to the set of names that analysis found.
    """
    wanted = set(signal.get("any", []))
    if not wanted:
        return False
    kind = signal.get("kind")
    if kind in evidence:
        return bool(wanted & evidence[kind])
    logger.warning(f"Unknown SDK fingerprint signal kind: {kind!r}")
    return False


class SdkFinder(InitPlugin):
    """
    Match the profile catalog against static analyses and score each profile.

    Consumes only analyses that already run (no new scanning): InterfaceFinder
    interface names, ClusterCollector executable basenames, LibrarySymbols
    exported symbols.
    """

    @cached_analysis
    def matches(self) -> list[dict]:
        """
        Scored profile matches, e.g.
        ``[{"name": "broadcom_hnd", "score": 3, "fired": [...], "enabled": True}]``.
        Only profiles with at least one fired signal are included.
        """
        profiles = load_profiles()

        iface_info = self.plugins.InterfaceFinder.interfaces or {}
        clusters = self.plugins.ClusterCollector.clusters
        lib_symbols = self.plugins.LibrarySymbols.library_info.get("symbols", {})

        evidence = {
            "interface": {i for group in iface_info.values() for i in group},
            "executable": set(clusters.get("executables", [])),
            "file": set(clusters.get("files", [])),
            "symbol": {sym for syms in lib_symbols.values() for sym in syms},
        }

        results = []
        for name, prof in profiles.items():
            fired = [
                s for s in prof.get("fingerprint", [])
                if _signal_fires(s, evidence)
            ]
            if not fired:
                continue
            min_signals = prof.get("enable_if", {}).get("min_signals", 2)
            score = len(fired)
            results.append({
                "name": name,
                "score": score,
                "fired": [{"kind": s.get("kind"), "any": s.get("any")} for s in fired],
                "enabled": score >= min_signals,
            })
        results.sort(key=lambda m: m["name"])
        return results

    def static_result(self) -> dict:
        return {"matches": self.matches}

    def verdict(self, name: str) -> dict | None:
        """The match entry for one profile, or None if it did not fire at all."""
        return next((m for m in self.matches if m["name"] == name), None)


# A CFE bootloader "envram" region is served to the firmware by the vendor
# `envrams` daemon, which reads it as a plain packed blob from a file (on the
# device, a UBIFS file on the `misc1` MTD partition). The packed format is a run
# of NUL-terminated ``key=value`` strings, double-NUL terminated, with no header
# or checksum -- established by disassembling `envrams` (it ``fread``s the whole
# file into a buffer and walks it with strlen/strchr('=')). We stage that blob at
# a persistent path the mount shim copies into the daemon's mount point.
ENVRAM_BLOB_PATH = "/rom/etc/nvram.nvm"


def _pack_envram(values: dict) -> bytes:
    """Pack ``{key: value}`` into the vendor envram blob format: NUL-terminated
    ``key=value`` entries, double-NUL terminated (empty trailing string)."""
    blob = bytearray()
    for k, v in values.items():
        blob += f"{k}={v}".encode()
        blob += b"\x00"
    blob += b"\x00"
    return bytes(blob)


def _profile_patch(
    plugin: InitPlugin,
    profile_name: str,
    tier: str = "libinject",
    default_tier: bool = True,
) -> dict | None:
    """
    Body shared by the per-profile patch classes: emit ``profile_name``'s bundle
    for the given fidelity ``tier`` (``bundles.<tier>``), setting ``plugin.enabled``
    from SdkFinder's confidence verdict (ENABLED when the fingerprint corroborates,
    else DISABLED -- a search candidate). Returns None (no patch) when no
    fingerprint signal fired at all, or when the profile defines no bundle for
    this tier (e.g. an SDK whose Tier-1 ``mtd`` model has not been built yet).

    ``default_tier`` gates enablement: the default (Tier-0 libinject) tier is
    baked in when the fingerprint corroborates, but a non-default tier (e.g.
    ``mtd``) is always emitted as a DISABLED candidate -- it carries higher- or
    additional-fidelity modeling that is opt-in (promoted by the search or the
    user), not automatically enabled just because the SDK was detected.

    A bundle may declare an ``envram:`` dict; it is packed into the vendor envram
    blob (see :func:`_pack_envram`) and materialized as a static file at
    :data:`ENVRAM_BLOB_PATH` (the ``envram`` key itself is dropped from the patch).
    """
    verdict = plugin.plugins.SdkFinder.verdict(profile_name)
    if verdict is None:
        return None
    prof = load_profiles().get(profile_name, {})
    bundles = prof.get("bundles") or {}
    bundle = bundles.get(tier)
    # Tolerate legacy single-bundle profiles by mapping `bundle:` onto Tier 0.
    if bundle is None and tier == "libinject":
        bundle = prof.get("bundle")
    if not bundle:
        return None
    envram = bundle.pop("envram", None)
    if envram:
        static_files = bundle.setdefault("static_files", {})
        static_files[ENVRAM_BLOB_PATH] = {
            "type": "inline_file",
            "contents": _pack_envram(envram),
            "mode": 0o644,
        }
    plugin.enabled = verdict["enabled"] and default_tier
    return bundle


class BroadcomHndProfile(InitPlugin):
    '''ASUSWRT / Broadcom HND profile, Tier-0 libinject bundle (et/robo switch + CFE nvram).'''
    patch_name = 'sdk.broadcom_hnd'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'broadcom_hnd', tier='libinject')


class BroadcomHndMtdProfile(InitPlugin):
    '''Broadcom HND Tier-1 (mtd) bundle: a data-faithful CFE-envram backing store
    for the vendor `envrams` daemon (packed nvram.nvm blob + a mount shim that
    stages it), emitted as the DISABLED candidate `sdk.broadcom_hnd.mtd`.

    envrams reads a store lib_inject cannot serve (it bypasses the nvram_get
    library API), so this is ADDITIVE to the Tier-0 libinject bundle rather than a
    replacement: promote it alongside `sdk.broadcom_hnd` for targets whose boot
    blocks on envrams. penguin has no real UBI/UBIFS emulation, so the actual
    misc1 UBI mount is shimmed rather than modeled -- see the profile YAML and the
    `scope the real MTD/UBI partition` follow-up.'''
    patch_name = 'sdk.broadcom_hnd.mtd'
    order = 136

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'broadcom_hnd', tier='mtd', default_tier=False)


class BroadcomHndBootProfile(InitPlugin):
    '''Broadcom HND boot-to-runtime bundle, SILICON half: model the SWMDK/BCM6300
    robo-switch probe (else cdk_dev_create fails and /sbin/rc reboots). The
    userland-generic post-envram blockers (the first-boot restore-defaults reboot
    and the stuck GPIO buttons) live in `sdk.asuswrt.boot` -- promote both. Emitted
    as the DISABLED candidate `sdk.broadcom_hnd.boot`; additive to the Tier-0
    libinject bundle.'''
    patch_name = 'sdk.broadcom_hnd.boot'
    order = 137

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'broadcom_hnd', tier='boot', default_tier=False)


class AsuswrtBootProfile(InitPlugin):
    '''ASUSWRT userland boot-to-runtime bundle (silicon-independent): neutralise
    the first-boot "## Restoring defaults ##" reboot(2) and report the libshared
    GPIO buttons as released. The switch probe is silicon-specific and lives in
    the silicon profile (e.g. `sdk.broadcom_hnd.boot`). Emitted as the DISABLED
    candidate `sdk.asuswrt.boot`; promote it for any ASUSWRT target regardless of
    silicon, alongside the silicon profile's own boot bundle.'''
    patch_name = 'sdk.asuswrt.boot'
    order = 138

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'asuswrt', tier='boot', default_tier=False)


class AsuswrtWanProfile(InitPlugin):
    '''ASUSWRT WAN-connected bundle (silicon-independent): stand up a tap-backed
    WAN interface via the VPN owned-interfaces feature and pin the WAN unit-0 nvram
    at it (immune to ASUSWRT's per-boot default-restore), so the WAN state machine
    reaches CONNECTED with a default route -- no real uplink or core.network
    required. Emitted as the DISABLED candidate `sdk.asuswrt.wan`; additive to
    `sdk.asuswrt.boot` (needs the box already at runtime).'''
    patch_name = 'sdk.asuswrt.wan'
    order = 139

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'asuswrt', tier='wan', default_tier=False)


class QualcommQsdkProfile(InitPlugin):
    '''ASUSWRT / Qualcomm QSDK profile, Tier-0 libinject bundle (libnvram DT_NEEDED shim + uClibc-eager nvram aliases).'''
    patch_name = 'sdk.qualcomm_qsdk'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'qualcomm_qsdk', tier='libinject')


class QualcommQsdkBootProfile(InitPlugin):
    '''Qualcomm QSDK boot-to-runtime bundle, SILICON half: shim /usr/sbin/ssdk_sh
    (the QCA SSDK switch control tool) with canned output so ASUSWRT's QCA8337
    switch/port-link detection works without the qca-ssdk kernel driver. The
    userland-generic blockers live in `sdk.asuswrt.boot` -- promote both. Emitted
    as the DISABLED candidate `sdk.qualcomm_qsdk.boot`; SOURCE-DERIVED from the
    RT-AC58U GPL, not yet boot-verified (needs a bootable QSDK rootfs).'''
    patch_name = 'sdk.qualcomm_qsdk.boot'
    order = 137

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'qualcomm_qsdk', tier='boot', default_tier=False)


class MediatekRalinkBootProfile(InitPlugin):
    '''MediaTek/Ralink APSoC boot-to-runtime bundle, SILICON switch: shim the
    raeth `mii_mgr` / `switch` register tools with canned output so switch
    bring-up is quiet without the raeth kernel driver (which does not load under
    emulation). Emitted as the DISABLED candidate `sdk.mediatek_ralink.boot`;
    config-only (static_files), analogous to the QCA ssdk_sh shim.'''
    patch_name = 'sdk.mediatek_ralink.boot'
    order = 137

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'mediatek_ralink', tier='boot', default_tier=False)


class NetgearAcosProfile(InitPlugin):
    '''Netgear ACOS profile, Tier-0 libinject bundle (ACOS nvram defaults + WAN_ith_CONFIG_GET shim).'''
    patch_name = 'sdk.netgear_acos'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'netgear_acos', tier='libinject')


class RealtekRtl819xProfile(InitPlugin):
    '''Realtek RTL819x profile, Tier-0 libinject bundle: serve the APMIB config
    surface from config (apmib_get/apmib_set aliased onto the lib_inject key/value
    store). Graduated from the former Slice-0 sdk.realtek alias group. apmib_init/
    reinit/update are stubbed to success by the generic tailored-alias layer
    (base_aliases), which this profile relies on -- apmib_init_HW returns NULL on a
    missing flash signature with no defaults fallback, so without that stub every
    apmib consumer bails at startup.'''
    patch_name = 'sdk.realtek_rtl819x'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'realtek_rtl819x', tier='libinject')


class RealtekRtl819xBootProfile(InitPlugin):
    '''Realtek RTL819x boot-to-runtime bundle, SILICON surface: model the flash
    MTD partitions (/proc/mtd + mtdblock nodes) the rcS mount and `flash` MIB tool
    touch directly, and answer the RTL8367/RTL8368 robo-switch control ioctls with
    success (gigabit boards). Emitted as the DISABLED candidate
    `sdk.realtek_rtl819x.boot`; additive to the Tier-0 libinject bundle.'''
    patch_name = 'sdk.realtek_rtl819x.boot'
    order = 137

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'realtek_rtl819x', tier='boot', default_tier=False)


class AvmFritzosProfile(InitPlugin):
    '''AVM FRITZ!OS profile, Tier-0 libinject bundle. Unlike the other SDK
    profiles this tier carries a PSEUDOFILE, not lib_inject symbol aliases:
    FRITZ!OS userland is uClibc (LD_PRELOAD-blind), so aliasing libtffs/libboxlib
    exports would not bind on their DT_NEEDED consumers. The LD_PRELOAD-independent
    surface it serves is the MANDATORY urlader boot environment
    (/proc/sys/urlader/environment) as a const_buf -- /etc/boot.d/1 hard-blocks the
    boot until that node exists, then reads the systemd.unit target from its
    kernel_args. The TFFS config-store char devices are the additive boot tier.'''
    patch_name = 'sdk.avm_fritzos'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'avm_fritzos', tier='libinject')


class AvmFritzosBootProfile(InitPlugin):
    '''AVM FRITZ!OS boot-to-runtime bundle, SILICON surface: model the TFFS
    config-store char devices (/proc/tffs, /dev/tffs/mtdN, /dev/tffs_userlog,
    /dev/tffs_panic) as read-after-write (stateful read + discard write) so
    libtffs tffs_write_value's writes read back and ioctls answer success.
    Emitted as the DISABLED candidate `sdk.avm_fritzos.boot`; additive to the
    Tier-0 libinject bundle (which already serves the mandatory urlader boot-env).
    Opt-in because read-after-write flash is higher-fidelity modeling, not needed
    merely to detect the SDK.'''
    patch_name = 'sdk.avm_fritzos.boot'
    order = 137

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'avm_fritzos', tier='boot', default_tier=False)
