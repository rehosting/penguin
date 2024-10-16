import os
import random
import shutil

from types import SimpleNamespace
from copy import deepcopy

from penguin.common import getColoredLogger
from .penguin_config import dump_config, hash_yaml_config, load_config, load_unpatched_config
from .manager import PandaRunner, calculate_score
from .graph_search import Worker # just for analyze_failures. Maybe refactor

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

    def add_solution(self, failure_name, solution, weight=0.5):
        """Add a potential solution to an existing failure"""
        if failure_name in self.failures:
            self.failures[failure_name]["solutions"].append({"solution": solution, "weight": weight})
        else:
            raise ValueError(f"Failure '{failure_name}' does not exist. Add it first.")

    def probabilistic_mitigation_selection(self):
        """Select independent failures to mitigate and pick one of their solutions."""
        selected_failures = []

        # Step 1: For each failure, decide probabilistically if it will be mitigated
        for failure_name, failure_data in self.failures.items():
            failure_weight = failure_data["weight"]
            if random.random() <= failure_weight:
                # Step 2: Select one solution for the chosen failure
                selected_failures.append(self._select_solution(failure_name))

        return selected_failures

    def _select_solution(self, failure_name):
        """Select a solution for a given failure based on solution weights"""
        solutions = self.failures[failure_name]["solutions"]
        if solutions:
            solution_weights = [s["weight"] for s in solutions]
            solution_idx = self._weighted_choice(solution_weights)
            selected_solution = solutions[solution_idx]["solution"]
            return failure_name, selected_solution
        else:
            return failure_name, None

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
        # load_unpatched_config (others take in the loaded config with patches alread
        # applied)
        self.base_config = load_unpatched_config(config_path)
        self.seen_configs = set()
        self.weights = DoublyWeightedSet() # Track failures -> [solutions] with weights

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

        # Bit of a hack, make a fake graph node with our config to analyze failures on
        fake_graph_node = SimpleNamespace(info=patched_config, exclusive=None)
        failures = Worker.analyze_failures(run_dir, fake_graph_node, 1, logger=self.logger)

        print(f"Saw {len(failures)} failures")
        for failure in failures:
            # TODO: add failure if it's new. Propose patches to solve it
            print("Failure: ", failure)

def patch_search(
    proj_dir, config_path, output_dir, timeout, max_iters=1000,
    nworkers=1, verbose=False
):
    PatchSearch(proj_dir, config_path, output_dir, timeout,
                max_iters, nworkers, verbose).run()
    
