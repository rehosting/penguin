import os
import shutil
from time import sleep

from typing import List
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed

from penguin.common import getColoredLogger, yaml
from .penguin_config import dump_config, hash_yaml_config, load_config, load_unpatched_config
from .manager import PandaRunner, calculate_score

class PatchMinmizer():
    def __init__(self, proj_dir, config_path, output_dir, timeout,
                 max_iters, nworkers, verbose):
        self.logger = getColoredLogger("penguin.patch_minmizer")
        self.proj_dir = proj_dir
        self.output_dir = output_dir
        self.timeout = timeout
        self.max_iters = max_iters
        self.nworkers = nworkers
        self.verbose = verbose
        self.patches_to_test = list()

        base_config = load_unpatched_config(config_path)
        self.original_config = base_config
        self.base_config = deepcopy(base_config)
        self.run_count = 0
        self.scores = dict() #run_index -> score
        self.runmap = dict() #run_index -> patchset

        # Gather all the candidate patches and our base config to include patches we need for exploration
        self.base_config["patches"] = list()
        for patch in base_config["patches"]:
            if not patch.endswith("base.yaml") and not patch.endswith("auto_explore.yaml"):
                self.patches_to_test.append(patch)
            else:
                self.base_config["patches"].append(patch)

        self.run_base = os.path.join(output_dir, "runs")
        os.makedirs(self.run_base, exist_ok=True)
        dump_config(self.base_config, os.path.join(output_dir, "base_config.yaml"))

        self.logger.setLevel("DEBUG" if verbose else "INFO")
        self.logger.info(f"Loaded {len(self.patches_to_test)} patches to test")
        self.logger.debug(f"Candidate patches: {self.patches_to_test}")

    def run_config(self, patchset, run_index):
        """
        This function runs a single configuration and returns the score
        Runs in parallel... so be careful with shared resources
        """
        score = {"empty": 0.0}
        run_dir = os.path.join(self.run_base, str(run_index))
        if os.path.isdir(run_dir):
            # Remove it
            shutil.rmtree(run_dir)
        os.makedirs(run_dir)
        self.logger.info(f"Running patchset {patchset} in {run_dir}")
        new_config = deepcopy(self.base_config)
        new_config["patches"].extend(patchset)
        conf_yaml = os.path.join(run_dir, "config.yaml")
        dump_config(new_config, conf_yaml)

        out_dir = os.path.join(run_dir, "output")
        os.makedirs(out_dir, exist_ok=True)

        try:
            PandaRunner().run(conf_yaml, self.proj_dir, out_dir,
                              timeout=self.timeout, verbose=self.verbose)

        except RuntimeError as e:
            # Uh oh, we got an error while running. Warn and continue
            self.logger.error(f"Could not run {run_dir}: {e}")
            return {}

        score = calculate_score(out_dir)
        with open(os.path.join(run_dir, "totalscore.txt"), "w") as f:
            total = float(sum(score.values()))
            f.write(f"{total}\n")

        return run_index, score

    def run_configs(self, patchsets: List[str]):
        with ThreadPoolExecutor(max_workers=self.nworkers) as executor:
            futures = []
            for patchset in patchsets:
                self.runmap[self.run_count] = deepcopy(patchset)
                futures.append(executor.submit(self.run_config, patchset, self.run_count))
                self.run_count += 1

            # Wait for all the submitted tasks to complete
            for future in as_completed(futures):
                try:
                    index, score = future.result()  # Optionally handle exceptions here
                    self.scores[index] = score
                except Exception as e:
                    print(f"Thread raised an exception: {e}")
                    self.logger.exception(e) # Show the full traceback
                    # Bail
                    executor.shutdown(wait=False)
                    break

    def config_still_viable(self, run_index):
        #Run 0 is always our baseline
        baseline = sum(self.scores[0].values())

        #Are we within 95% of the baseline?
        our_score = sum(self.scores[run_index].values())
        self.logger.info(f"Score for {run_index}: {our_score} (baseline: {baseline})")
        return our_score >= 0.95 * baseline

    def get_best_patchset(self):
        """
        If we don't assume independence, we have to run every combination of patches
        Then we could get the best one this way
        """
        best = (0, self.original_config["patches"])
        for index, score in self.scores.items():
            if self.config_still_viable(index) and len(self.runmap[index]) < len(best):
                best = (index, self.runmap[index])

        return best

    def run(self):
        #First, establish a baseline score by running the base config.
        #We're going to do a binary search, so might as well run the other two halves as well

        #It is assumed by other code that run 0 is the baseline 

        patchsets=[self.patches_to_test] #our first patchset is the full set of patches

        while self.run_count < self.max_iters:
            first_half_index = self.run_count + 1
            second_half_index = self.run_count + 2
            patchsets.append(set(self.patches_to_test[:len(self.patches_to_test)//2]))
            patchsets.append(set(self.patches_to_test[len(self.patches_to_test)//2:]))

            self.run_configs(patchsets)

            first_half = self.config_still_viable(first_half_index)
            second_half = self.config_still_viable(second_half_index)
            if first_half and second_half:
                self.logger.error("Config bisection had both halves pass. This is unexpected!!")
                return
            elif not first_half and not second_half:
                self.logger.info("Config bisection had both halves fail. Time to move slowly")
                break
            elif first_half:
                self.logger.info("First half passed, second half failed. Considering first half")
                self.patches_to_test = patchsets[1]
            else:
                self.logger.info("First half failed, second half passed. Considering second half")
                self.patches_to_test = patchsets[2]

            patchsets.clear()
            if len(self.patches_to_test) == 1:
                self.logger.info("Only one patch left. Stopping")
                return self.patches_to_test

        #Now we are done with the binary search. If we assume independence, we'll generate a config without each patch
        run_tracker = dict()
        for i, patch in enumerate(self.patches_to_test, start=self.run_count):
            if i >= self.max_iters:
                self.logger.info("Hit max iterations. Stopping")
                break
            patchset = deepcopy(self.patches_to_test)
            patchset.remove(patch)
            patchsets.append(patchset)
            run_tracker[i] = patch

        self.run_configs(patchsets)

        for i, patch in run_tracker.items():
            if self.config_still_viable(i):
                self.logger.info(f"Removing {patch} from consideration, appears unecessary")
                self.patches_to_test.remove(patch)

        return self.patches_to_test

def minimize(proj_dir, config_path, output_dir, timeout, max_iters=1000,
                 nworkers=1, verbose=False):
    pm = PatchMinmizer(proj_dir, config_path, output_dir, timeout, max_iters, nworkers, verbose)
    pm.run()
    print(f"Required patchset: {pm.patches_to_test}")
