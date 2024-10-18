import os
import shutil
from time import sleep

from typing import List
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed

from penguin.common import getColoredLogger, yaml
from .penguin_config import dump_config, hash_yaml_config, load_config, load_unpatched_config
from .manager import PandaRunner, calculate_score
from .graph_search import Worker # just for analyze_failures. Maybe refactor
from .graphs import Failure, Mitigation
from .search_utils import MABWeightedSet, ConfigSearch


class PatchSearch(ConfigSearch):
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
        self.weights = MABWeightedSet() # Track failures -> [solutions] with weights

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
            self.weights.add_failure(name, allow_none=not always)  # Must mitigate if it's one of always
            self.weights.add_solution(name, patch)

        # Create a few patches after the fact (TODO: should this happen in gen_config?), one for
        # each potential init. If there's only 1 already it will be in base and this is unnecessary
        with open(os.path.join(self.proj_dir, "static", "InitFinder.yaml")) as f:
            init_choices = yaml.safe_load(f)

        if len(init_choices) > 1:
            failure_name = "static.potential.init_finder"
            self.weights.add_failure(failure_name, allow_none=False)
            # Create init patches and add to weights
            for init in init_choices:
                mit_path = os.path.join(self.patch_dir, f"init_{init.replace('/', '_')}.txt")
                with open(mit_path, "w") as f:
                    yaml.dump({"env": {"igloo_init": init}}, f)

                mit_path = mit_path.replace(self.proj_dir, "")
                if mit_path.startswith("/"):
                    mit_path = mit_path[1:]
                self.weights.add_solution(failure_name, mit_path)


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
            #for _ in range(10):
            #    # XXX: How to shutdown better? We want to see if we get a new config
            #    # after currently-running ones finish
            #    sleep(30)
            #    config, selection = self.generate_new_config()
            #if not config:
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
        #for f in failures:
        #    self.logger.info(f"\tRun {run_index} sees failure: {f} with patch_name {f.patch_name}")

        # Report on failures. TODO: do we want to write these down or just log?
        with open(os.path.join(run_dir, "failures.yaml"), "w") as f:
            yaml.dump([fail.to_dict() for fail in failures], f)

        for failure in failures:
            # TODO: if we do a learning config it shows up as distinct failures
            # while we want to treat it as a single failure
            is_new = False
            try:
                self.weights.add_failure(failure.patch_name)
                is_new = True
                #self.logger.info("\tNew failure: " + failure.patch_name)
            except ValueError:
                # It's already in there. Can't just check first, because we need lock
                # TODO: how should we prioritize the weight of new failures?
                #self.logger.info("\tExisting failure: " + failure.patch_name)
                pass

            # Now let's add potential solutions

            mitigations = self.find_mitigations(failure, patched_config)
            if not len(mitigations) and is_new:
                self.logger.warning(f"New failure {failure} has no mitigations?")

            for mitigation in mitigations:
                if mitigation.patch is None:
                    self.logger.warning(f"Mitigation {mitigation} has no patch. Ignore")
                    continue

                # Need to create YAML file for mitigation.patch on disk in our
                # patches dir
                hsh = hash_yaml_config(mitigation.patch)[:6]
                mit_path = os.path.join(self.patch_dir,
                                              f"{failure.type}_{failure.patch_name}_{hsh}.yaml")

                if not os.path.isfile(mit_path):
                    with open(mit_path, "w") as f:
                        yaml.dump(mitigation.patch, f)
                    self.logger.info(f"\t\tFound new potential {mitigation}") # XXX cached state between runs will make this rare

                # Make it a relative path to proj_dir
                mit_path = mit_path.replace(self.proj_dir, "")
                if mit_path.startswith("/"):
                    mit_path = mit_path[1:]

                # Intentionally hitting this even if the hash exists, we might want to be
                # doing some re-weighting in self.weights - it will ignore if duplicated
                self.weights.add_solution(failure.patch_name, mit_path, exclusive=mitigation.exclusive)

        with open(os.path.join(out_dir, "weights.txt"), "w") as f:
            f.write(str(self.weights))




# Entrypoint for __main__
def patch_search(proj_dir, config_path, output_dir, timeout, max_iters=1000,
                 nworkers=1, verbose=False):
    p = PatchSearch(proj_dir, config_path, output_dir, timeout,
                       max_iters, nworkers, verbose)
    p.run()
    print(p.weights)
