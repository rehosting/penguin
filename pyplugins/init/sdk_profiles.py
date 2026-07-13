"""
SDK profiles: fingerprint common silicon SDKs from static analyses and emit the
config bundle each SDK tends to need.

A *profile* is a catalog YAML (``profiles/<name>.yaml``) with a fingerprint and
a bundle. :class:`SdkFinder` scores every profile's fingerprint against analyses
that already run (InterfaceFinder, ClusterCollector, LibrarySymbols) -- it is the
consumer those analyses were missing. Each profile then has a patch class (e.g.
:class:`BroadcomHndProfile`) that emits the bundle as ``sdk.<name>``, ENABLED
when the fingerprint corroborates (>= ``enable_if.min_signals``) and DISABLED (a
search candidate, not a baked-in default) otherwise.

Slice 1 ships one profile (``broadcom_hnd``) with an explicit patch class,
mirroring the Slice-0 per-SDK alias classes; a generic catalog-driven emitter is
deferred until several profiles exist.
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


def _profile_patch(plugin: InitPlugin, profile_name: str) -> dict | None:
    """
    Body shared by the per-profile patch classes: emit ``profile_name``'s bundle,
    setting ``plugin.enabled`` from SdkFinder's confidence verdict (ENABLED when
    the fingerprint corroborates, else DISABLED -- a search candidate). Returns
    None (no patch) when no fingerprint signal fired at all.
    """
    verdict = plugin.plugins.SdkFinder.verdict(profile_name)
    if verdict is None:
        return None
    plugin.enabled = verdict["enabled"]
    prof = load_profiles().get(profile_name, {})
    return prof.get("bundle") or None


class BroadcomHndProfile(InitPlugin):
    '''ASUSWRT / Broadcom HND profile bundle (et/robo switch + CFE nvram).'''
    patch_name = 'sdk.broadcom_hnd'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'broadcom_hnd')


class QualcommQsdkProfile(InitPlugin):
    '''ASUSWRT / Qualcomm QSDK profile bundle (libnvram DT_NEEDED shim + uClibc-eager nvram aliases).'''
    patch_name = 'sdk.qualcomm_qsdk'
    order = 135

    def patch(self, ctx: InitContext) -> dict | None:
        return _profile_patch(self, 'qualcomm_qsdk')
