import os
import random
import shutil

from typing import List
from copy import deepcopy

from penguin.common import getColoredLogger, yaml
from .penguin_config import dump_config, hash_yaml_config, load_config, load_unpatched_config
from .manager import PandaRunner, calculate_score
from .graph_search import Worker # just for analyze_failures. Maybe refactor
from .utils import get_mitigation_providers
from .graphs import Failure, Mitigation

class DoublyWeightedSet:
    def __init__(self):
        # Store failures as a dictionary with weights and their potential solutions
        self.failures = {}

    def add_failure(self, failure_name, weight=0.5):
        """Add a failure with a specific weight (default 0.5)"""
        if failure_name not in self.failures:
            self.failures[failure_name] = {"weight": weight, "solutions": []}
        else:
            raise ValueError(f"Failure '{failure_name}' already exists.")

    def add_solution(self, failure_name, solution, weight=0.5, exclusive=False):
        """Add a potential solution to an existing failure"""
        if failure_name in self.failures:
            self.failures[failure_name]["solutions"].append({"solution": solution, "weight": weight, "exclusive": exclusive})
        else:
            raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")

    def probabilistic_mitigation_selection(self):
        """Select independent failures to mitigate and pick one of their solutions."""
        selected_failures = []
        have_exclusive = False

        # Step 1: For each failure, decide probabilistically if it will be mitigated
        for failure_name, failure_data in self.failures.items():
            # If there are no solutions, we can't mitigate the failure - skip
            if not failure_data["solutions"]:
                continue
            failure_weight = failure_data["weight"]
            if random.random() <= failure_weight:
                # Step 2: Select one solution for the chosen failure
                # if we get one
                soln = self._select_solution(failure_name, can_be_exclusive=
                                             not have_exclusive)
                if soln[1] is not None:
                    selected_failures.append(soln)
                    have_exclusive |= soln[2]

        return selected_failures

    def _select_solution(self, failure_name, can_be_exclusive=True):
        """Select a solution for a given failure based on solution weights"""
        # First select all potential solutions. If not can_be_exclusive, filter out
        # exclusive solutions
        solutions = [x for x in self.failures[failure_name]["solutions"] \
                     if not x["exclusive"] or can_be_exclusive]
        if solutions:
            solution_weights = [s["weight"] for s in solutions]
            solution_idx = self._weighted_choice(solution_weights)
            selected_solution = solutions[solution_idx]["solution"]
            is_exclusive = solutions[solution_idx]["exclusive"]
            return failure_name, selected_solution, is_exclusive
        else:
            return failure_name, None, False

    def _weighted_choice(self, weights):
        """Helper function to make a weighted choice from a list of weights"""
        total = sum(weights)
        rand_val = random.uniform(0, total)
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if rand_val < cumulative:
                return i
        return len(weights) - 1  # Fallback to last index
    
    def __str__(self):
        """Custom string representation to show failures and their solutions"""
        output = ""
        for failure, details in self.failures.items():
            output += f"Failure: {failure} (Weight: {details['weight']})\n"
            for sol in details["solutions"]:
                output += f"  - Solution: {sol['solution']} (Weight: {sol['weight']})\n"
        return output

class PatchSearch:
    def __init__(self, proj_dir, config_path, output_dir, timeout,
                 max_iters, nworkers, verbose):
        self.logger = getColoredLogger("penguin.patch_search")
        self.proj_dir = proj_dir
        self.output_dir = output_dir
        self.timeout = timeout
        self.max_iters = max_iters
        self.nworkers = nworkers
        self.verbose = verbose

        if self.nworkers != 1:
            self.logger.error("nworkers > 1 not supported yet - setting to 1")
            self.nworkers = 1

        # XXX unlike other searches, we take config path and load ourselves with
        # load_unpatched_config (others take in the loaded config with patches already
        # applied)
        self.base_config = load_unpatched_config(config_path)
        self.seen_configs = set()
        self.weights = DoublyWeightedSet() # Track failures -> [solutions] with weights

        self.patch_dir = os.path.join(self.proj_dir, "dynamic_patches")
        os.makedirs(self.patch_dir, exist_ok=True)

        self.run_base = os.path.join(output_dir, "runs")
        os.makedirs(self.run_base, exist_ok=True)
        dump_config(self.base_config, os.path.join(output_dir, "base_config.yaml"))

        # Initially we'll have our static patches available in ./proj_dir/auto_patches
        # We'll want to run with some of them - but not all are created equally!
        # TODO: figure out how to handle these - we might want to test if our
        # shims are causing problems (i.e., busybox) and disable if so
        # We can try with different nvram sources enabled/disabled
        # We probably want base and auto_patch applied always.

        print("Initial patches available:")
        for patch in self.base_config['patches']:
            friendly_name = patch.split("/")[-1].replace(".yaml", "")
            print("\t*", friendly_name)
            if friendly_name in ["base", "auto_explore", "libinject.core"]:
                name = f"static.default.{friendly_name}"
                # We always want these, and the single solution should always be applied
                self.weights.add_failure(name, 1.0)
                self.weights.add_solution(name, patch, 1.0) 
            else:
                name = f"static.potential.{friendly_name}"
                # TODO: we do actually have some groups right off the bat, but they
                # could actually be combined - e.g., select one of our nvram sources
                self.weights.add_failure(name, 0.5) # We might want it. Who knows
                self.weights.add_solution(name, patch, 0.5) # This might help. Who knows


    def generate_new_config(self, tries=10):
        '''
        Generate a unique config probabilistically
        '''
        def _generate_config():
            selected_results = self.weights.probabilistic_mitigation_selection()
            # We now have a series of patches that have been selected to apply
            # XXX: Do we know the corresponding failures? Whatever, let's just do it
            # for now
            new_config = deepcopy(self.base_config)
            new_config['patches'] = [s[1] for s in selected_results]
            return new_config

        for _ in range(tries):
            new_config = _generate_config()
            new_hash = hash_yaml_config(new_config)
            if new_hash not in self.seen_configs:
                self.seen_configs.add(new_hash)
                return new_config

    def run(self):
        '''
        Entrypoint for the patch search.
        '''
        for idx in range(self.max_iters):
            next_config = self.generate_new_config()
            if not next_config:
                break
            self.run_iteration(idx, next_config)

    def run_iteration(self, run_index, config):
        '''
        Run a single configuration. Update self.available_configs??
        '''
        self.logger.info(f"Starting iteration {run_index} with patches: {config['patches']}")

        run_dir = os.path.join(self.run_base, str(run_index))
        if os.path.isdir(run_dir):
            # Remove it
            shutil.rmtree(run_dir)
        os.makedirs(run_dir)

        # Write config to disk
        dump_config(config, os.path.join(run_dir, "config.yaml"))

        # Run the configuration
        conf_yaml = os.path.join(run_dir, "config.yaml")
        out_dir = os.path.join(run_dir, "output")
        os.makedirs(out_dir, exist_ok=True)

        try:
            PandaRunner().run(conf_yaml, self.proj_dir, out_dir,
                              timeout=self.timeout, verbose=self.verbose)
        except RuntimeError as e:
            # Uh oh, we got an error while running. Warn and continue
            self.logger.error(f"Could not run {run_dir}: {e}")
            return

        # Now, get the score and failures
        score = calculate_score(out_dir)
        with open(os.path.join(run_dir, "score.txt"), "w") as f:
            total = float(sum(score.values()))
            f.write(f"{total}\n")

        # TODO: update weights of patches we had selected based on score

        # Load from disk to get config with patches applied for analyze_failures?
        # Not sure if it matters - maybe we can use config directly?
        # XXX: config['core']['auto_patching'] better be false or it might pull in more?
        patched_config = load_config(self.proj_dir, conf_yaml)

        failures = self.analyze_failures(patched_config, run_dir)

        # Report on failures. TODO: do we want to write these down or just log?
        with open(os.path.join(run_dir, "failures.yaml"), "w") as f:
            yaml.dump([fail.to_dict() for fail in failures], f)
        print(f"Saw {len(failures)} failures")
        for failure in failures:
            print("Failure: ", failure)

            if failure not in self.weights.failures:
                # TODO: how should we prioritize the weight of new failures?
                self.weights.add_failure(failure, 0.5)
            else:
                # TODO: should we increase the weight whenever we see a failure again?
                pass

            # Now let's add potential solutions

            mitigations = self.find_mitigations(failure, patched_config)
            for mitigation in mitigations:
                self.logger.info(f"Mitigation: {mitigation}")

                if mitigation.patch is None:
                    self.logger.warning(f"Mitigation {mitigation} has no patch. Ignore")
                    continue

                # We don't need to normalize soln weights, but it's easier to reason about
                # if they're sort of normal.
                # If it's an exclusive mitigation, we make the weight low so we only
                # try it if we don't have better options
                weight = 1 / len(mitigations)
                # TODO: should we use mitigation['info']['weight'] if it exists?

                if mitigation.exclusive:
                    # TODO: should we handle exclusives now? Or when selecting?
                    # If it's at selection time, we'll need to track mitigations then
                    weight = 0.01

                # Need to create YAML file for mitigation.patch on disk in our 
                # patches dir
                hsh = hash_yaml_config(mitigation.patch)
                mit_path = os.path.join(self.patch_dir,
                                              f"mitigation_{hsh}.yaml")
                with open(mit_path, "w") as f:
                    yaml.dump(mitigation.patch, f)

                self.weights.add_solution(failure, mit_path, weight, exclusive=mitigation.exclusive)

    def find_mitigations(
        self, failure: Failure, config
    ) -> List[Mitigation]:
        results = []
        # Lookup the plugin that can handle this failure
        analysis = get_mitigation_providers(config)[failure.type]
        for m in analysis.get_potential_mitigations(config, failure) or []:
            if not isinstance(m, Mitigation):
                raise TypeError(
                    f"Plugin {analysis.ANALYSIS_TYPE} returned a non-Mitigation object {m}"
                )
            self.logger.info(f"Plugin {analysis.ANALYSIS_TYPE} suggests mitigation {m}")
            results.append(m)
        return results

    def analyze_failures(self, config, run_dir, exclusive=None):
        """
        After we run a configuration, do our post-run analysis of failures.
        Run each PyPlugin that has a PenguinAnalysis implemented. Ask each to 
        identify failures.
        """

        fails = []  # (id, type, {data})
        output_dir = os.path.join(run_dir, "output")

        mitigation_providers = get_mitigation_providers(config)

        # For an exclusive config, only query the exclusive provider
        if exclusive is not None:
            if exclusive not in mitigation_providers:
                raise ValueError(
                    f"Cannot use exclusive {exclusive} as it's not a mitigation provider"
                )
            mitigation_providers = {
                exclusive: mitigation_providers[exclusive]
            }

        for plugin_name, analysis in mitigation_providers.items():
            try:
                failures = analysis.parse_failures(output_dir)
            except Exception as e:
                self.logger.error(e)
                raise e

            for failure in failures or []:
                if not isinstance(failure, Failure):
                    raise TypeError(
                        f"Plugin {plugin_name} returned a non-Failure object {failure}"
                    )
                fails.append(failure)

        # We might have duplicate failures, but that's okay, caller will dedup?
        return fails


# Entrypoint for __main__
def patch_search(proj_dir, config_path, output_dir, timeout, max_iters=1000,
                 nworkers=1, verbose=False):
    return PatchSearch(proj_dir, config_path, output_dir, timeout,
                       max_iters, nworkers, verbose).run()
    