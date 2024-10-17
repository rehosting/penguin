import os
import random
import shutil
import threading
import math

from typing import List
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        self.past_scores = {}
        self.alpha = 0.01  # Learning rate for weight updates
        self.lock = threading.Lock()

    def add_failure(self, failure_name, weight=0.5, always_select=False):
        """Add a failure with a specific weight (default 0.5) and a flag to always select it."""
        with self.lock:
            if failure_name not in self.failures:
                self.failures[failure_name] = {
                    "weight": weight,
                    "solutions": [],
                    "always_select": always_select  # Mark failures that should always be selected
                }
            else:
                raise ValueError(f"Failure '{failure_name}' already exists.")

    def add_solution(self, failure_name, solution, weight=0.5, exclusive=False, always_select=False):
        """Add a potential solution to an existing failure, with an option to always select."""
        with self.lock:
            if failure_name in self.failures:
                if solution not in [x["solution"] for x in self.failures[failure_name]["solutions"]]:
                    self.failures[failure_name]["solutions"].append({
                        "solution": solution,
                        "weight": weight,
                        "exclusive": exclusive,
                        "always_select": always_select  # Mark solution that should always be applied
                    })
            else:
                raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")


    def probabilistic_mitigation_selection(self):
        """Select independent failures to mitigate and pick one of their solutions."""
        selected_failures = []  # (failure_name, solution)
        have_exclusive = False

        # Step 1: For each failure, decide probabilistically if it will be mitigated
        with self.lock:
            for failure_name, failure_data in self.failures.items():
                # If there are no solutions, skip
                if not failure_data["solutions"]:
                    continue

                # If the failure or solution is marked as always_select, skip the probabilistic check
                if failure_data.get("always_select", False):
                    selected_solution = failure_data["solutions"][0]["solution"]
                    selected_failures.append((failure_name, selected_solution))
                    continue

                failure_weight = failure_data["weight"]
                if random.random() <= failure_weight:
                    # Step 2: Select one solution for the chosen failure
                    soln = self._select_solution(failure_name, can_be_exclusive=not have_exclusive)
                    if soln[1] is not None:
                        selected_failures.append((soln[0], soln[1]))
                        have_exclusive |= (soln[2] is not None)

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
                output += f"  - Solution: {sol['solution']} (Weight: {sol['weight']}, Exclusive: {sol['exclusive']})\n"
        return output

    def report_result(self, selected_failures, final_score):
        """
        Update the weights for both failures and solutions based on the observed result (final_score).
        """
        with self.lock:
            for failure_name, selected_solution in selected_failures:
                # Initialize history of scores for this failure-solution pair if not present
                key = (failure_name, selected_solution)
                if key not in self.past_scores:
                    self.past_scores[key] = []  # Make sure it's initialized as a list

                # Append the new score to this failure-solution's history
                self.past_scores[key].append(final_score)

                # Normalize score based on the history of past scores for this pair
                normalized_score = self._normalize_score(key)

                # Update the failure and solution weights based on the normalized score
                failure_data = self.failures[failure_name]
                failure_weight = failure_data["weight"]
                expected_score = self._expected_score(key)

                error_term = normalized_score - expected_score
                new_failure_weight = failure_weight + self.alpha * error_term
                failure_data["weight"] = max(0.0, min(1.0, new_failure_weight))  # Keep within [0, 1]

                # Update the solution weight (with Bayesian-like updating)
                solution_idx = next(i for i, s in enumerate(failure_data["solutions"])
                                    if s["solution"] == selected_solution)
                solution_data = failure_data["solutions"][solution_idx]
                solution_weight = solution_data["weight"]
                posterior_weight = self._bayesian_update(solution_weight, normalized_score)
                solution_data["weight"] = posterior_weight


    def _normalize_score(self, key):
        """Normalize the score based on the history of past scores for the given key (failure, solution)."""
        if key not in self.past_scores or not self.past_scores[key]:
            return 0.5  # Default score if no history exists

        scores = self.past_scores[key]
        if not isinstance(scores, list):  # Type check to catch errors
            raise TypeError(f"Expected list for past_scores[{key}], got {type(scores)}")
        # Check each value, ensure it's an int
        for score in scores:
            if not isinstance(score, (int, float)):
                raise TypeError(f"Expected int/float for past_scores[{key}], got {type(score)}: {score}")

        mean_score = sum(scores) / len(scores)
        score_range = max(scores) - min(scores) if len(scores) > 1 else 1
        return (scores[-1] - mean_score) / score_range

    def _expected_score(self, key):
        """Estimate the expected score for the given failure and solution based on past performance."""
        if key not in self.past_scores or not self.past_scores[key]:
            return 0.5  # Default expected score if no history exists

        scores = self.past_scores[key]
        if not isinstance(scores, list):  # Type check to ensure correct type
            raise TypeError(f"Expected list for past_scores[{key}], got {type(scores)}")

        return sum(scores) / len(scores)


    def _bayesian_update(self, prior_weight, score):
        """Perform a Bayesian update of the solution weight."""
        likelihood = math.exp(-abs(score - 0.5))  # A simple likelihood function
        posterior_weight = prior_weight * likelihood
        return posterior_weight / (posterior_weight + (1 - prior_weight) * (1 - likelihood))


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
            always = friendly_name in ["base", "auto_explore", "libinject.core", "force_www"]
            name = f"static.potential.{friendly_name}"
            self.weights.add_failure(name, 1.0, always_select = always)
            self.weights.add_solution(name, patch, 1.0, always_select = always)

        # TODO: init binary selection -> always select failure with solutions spanning init choices?
        # Should we make multiple patches in gen_config? Should we read static/InitFinder.yaml here and make one for each?


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
            return (new_config, selected_results)

        for _ in range(tries):
            (new_config, selection) = _generate_config()
            new_hash = hash_yaml_config(new_config)
            if new_hash not in self.seen_configs:
                self.seen_configs.add(new_hash)
                return (new_config, selection)

        return None, None

    def run(self):
        '''
        Entrypoint for the patch search.
        '''
        with ThreadPoolExecutor(max_workers=self.nworkers) as executor:
            futures = []
            for idx in range(self.max_iters):
                futures.append(executor.submit(self.run_iteration, idx))

            # Wait for all the submitted tasks to complete
            for future in as_completed(futures):
                try:
                    future.result()  # Optionally handle exceptions here
                except Exception as e:
                    print(f"Thread raised an exception: {e}")
                    self.logger.exception(e) # Show the full traceback
                    # Bail
                    executor.shutdown(wait=False)
                    return

    def run_iteration(self, run_index):
        '''
        Run a single configuration. Update self.available_configs??
        '''
        # Select config immediately prior to running (so we're not queuing up stale ones)
        self.logger.info(f"Idx {run_index} generate new config...")
        config, selection = self.generate_new_config()
        if not config:
            self.logger.info(f"Idx {run_index} no new config - done?")
            return

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

        self.process_results(run_index, run_dir, out_dir, conf_yaml, selection)

    def process_results(self, run_index, run_dir, out_dir, conf_yaml, selection):
        # Now, get the score and failures
        score = calculate_score(out_dir)
        total = float(sum(score.values()))

        with open(os.path.join(run_dir, "score.txt"), "w") as f:
            f.write(f"{total}\n")
        self.logger.info(f"Score for run {run_index}: {total}")

        self.weights.report_result(selection, total)

        # TODO: update weights of patches we had selected based on score

        # Load from disk to get config with patches applied for analyze_failures?
        # Not sure if it matters - maybe we can use config directly?
        # XXX: config['core']['auto_patching'] better be false or it might pull in more?
        patched_config = load_config(self.proj_dir, conf_yaml)

        failures = self.analyze_failures(patched_config, run_dir)

        # Report on failures. TODO: do we want to write these down or just log?
        with open(os.path.join(run_dir, "failures.yaml"), "w") as f:
            yaml.dump([fail.to_dict() for fail in failures], f)
        for failure in failures:
            # TODO: if we do a learning config it shows up as distinct failures
            # while we want to treat it as a single failure
            try:
                self.weights.add_failure(failure.patch_name, 0.5)
            except ValueError:
                # It's already in there. Can't just check first, because we need lock
                # TODO: how should we prioritize the weight of new failures?
                pass

            # Now let's add potential solutions

            mitigations = self.find_mitigations(failure, patched_config)
            for mitigation in mitigations:
                if mitigation.patch is None:
                    self.logger.warning(f"Mitigation {mitigation} has no patch. Ignore")
                    continue

                # TODO: What do we want to do for weights? Lower for exclusive
                # because we should select other solutions first (if they exist within the
                # failure).
                weight = 0.1 if mitigation.exclusive else 1.0

                # Need to create YAML file for mitigation.patch on disk in our
                # patches dir
                hsh = hash_yaml_config(mitigation.patch)[:6]
                mit_path = os.path.join(self.patch_dir,
                                              f"{failure.type}_{failure.patch_name}_{hsh}.yaml")

                if not os.path.isfile(mit_path):
                    with open(mit_path, "w") as f:
                        yaml.dump(mitigation.patch, f)

                    # Make it a relative path to proj_dir
                    mit_path = mit_path.replace(self.proj_dir, "")
                    if mit_path.startswith("/"):
                        mit_path = mit_path[1:]
                    self.logger.info(f"Found new potential {mitigation}")

                # Intentionally hitting this even if the hash exists, we might want to be
                # doing some re-weighting in self.weights - it will ignore if duplicated
                self.weights.add_solution(failure.patch_name, mit_path, weight, exclusive=mitigation.exclusive)

        with open(os.path.join(out_dir, "weights.txt"), "w") as f:
            f.write(str(self.weights))


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
