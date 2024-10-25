import os
import shutil
from time import sleep

from typing import List
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed

from penguin.common import getColoredLogger, yaml, frozenset_to_dict, dict_to_frozenset
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
        self.binary_search = True
        self.dynamic_patch_dir = os.path.join(self.proj_dir, "dynamic_patches")

        base_config = load_unpatched_config(config_path)
        self.original_config = base_config
        self.base_config = deepcopy(base_config)
        self.run_count = 0
        self.scores = dict() #run_index -> score
        self.runmap = dict() #run_index -> patchset

        #TODO: use FICD to set timeout if timeout parameter. Warn if FICD not reached
        #      add an FICD option to run until FICD (which might have to do the baseline single-threaded)

        # Gather all the candidate patches and our base config to include patches we need for exploration
        self.base_config["patches"] = list()
        for patch in base_config["patches"]:
            if not patch.endswith("base.yaml") and not patch.endswith("auto_explore.yaml"):
                self.patches_to_test.append(patch)
            else:
                self.base_config["patches"].append(patch)

        self.split_overlapping_patches()

        self.run_base = os.path.join(output_dir, "runs")
        os.makedirs(self.run_base, exist_ok=True)
        dump_config(self.base_config, os.path.join(output_dir, "base_config.yaml"))

        self.logger.setLevel("DEBUG" if verbose else "INFO")
        self.logger.info(f"Loaded {len(self.patches_to_test)} patches to test")
        self.logger.debug(f"Candidate patches: {self.patches_to_test}")

    @staticmethod
    def lists_overlap(list1, list2):
        overlap = list()
        for item in list1:
            if item in list2:
                overlap.append(item)
        return overlap

    @staticmethod
    def dicts_overlap(dict1, dict2):
        """
        Returns a dict of the overlapping keys and values
        """
        overlap = dict()
        for key in dict1:
            if key in dict2:
                if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                    sub_overlap = PatchMinmizer.dicts_overlap(dict1[key], dict2[key])
                    if sub_overlap:
                        overlap[key] = sub_overlap
                elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
                    sub_overlap = PatchMinmizer.lists_overlap(dict1[key], dict2[key])
                    if sub_overlap:
                        overlap[key] = sub_overlap
                elif dict1[key] == dict2[key]:
                    overlap[key] = dict1[key]
        return overlap

    @staticmethod
    def diff_dicts(dict1, dict2):
        """
        Returns the difference of dict1 - dict2
        i.e., the keys and values that are in dict1 not in dict2
        """
        diff = dict()

        for key in dict1:
            if key in dict2:
                if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                    sub_diff = dict_remove(dict1[key], dict2[key])
                    if sub_diff:
                        diff[key] = sub_diff
                elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
                    new_list = [item for item in dict1[key] if item not in dict2[key]]
                    if new_list:
                        diff[key] = new_list
                elif dict1[key] != dict2[key]:
                    diff[key] = dict1[key]
            else:
                diff[key] = dict1[key]

        return diff

    def split_overlapping_patches(self):
        """
        If we have overlapping patches, we attempt to preserve orthoganality by splitting them
        Ensuring that each unique configuration option is in only one patch
        Not fully tested on three-way overlaps
        """
        overlapping = dict()
        for patch in self.patches_to_test:
            for other in self.patches_to_test:
                if patch != other:
                    patch_config = load_unpatched_config(os.path.join(self.proj_dir, patch))
                    other_config = load_unpatched_config(os.path.join(self.proj_dir, other))
                    overlap = PatchMinmizer.dicts_overlap(patch_config, other_config)
                    if overlap:
                        overlap_key = dict_to_frozenset(overlap)
                        if overlap_key not in overlapping:
                            overlapping[overlap_key] = set()
                        overlapping[overlap_key].update({patch, other})
        if overlapping:
            self.logger.info("Overlapping patches detected")
            os.makedirs(self.dynamic_patch_dir, exist_ok=True)

        for overlap, patches in overlapping.items():
            overlap_dict = frozenset_to_dict(overlap)
            new_patch_path = os.path.join(self.dynamic_patch_dir,
                                          f"overlap_{'_'.join(overlap_dict.keys())}_{hash_yaml_config(overlap_dict)[-6:]}.yaml")
            new_patches = [(new_patch_path,frozenset_to_dict(overlap))]
            self.logger.info(f"Option {overlap_dict} is in multiple patches: {patches}")
            for old_patch in patches:
                old_patch_path = os.path.join(self.proj_dir, old_patch)
                old_patch_config = load_unpatched_config(old_patch_path)
                new_patch = deepcopy(old_patch_config)
                diff = PatchMinmizer.diff_dicts(new_patch, frozenset_to_dict(overlap))

                old_patch_path = os.path.join(self.proj_dir, old_patch)
                #Create the diff patch in dynamic dir still (originally used original dir, but would be misleading for static
                diff_path = os.path.join(self.dynamic_patch_dir,
                                         f"diff_{hash_yaml_config(diff)[-6:]}_{os.path.basename(old_patch_path)}")
                if diff:
                    #we might've emptied a patch
                    new_patches.append((diff_path, diff))
                self.logger.debug(f"Removing {old_patch} from consideration due to overlap")
                self.patches_to_test.remove(old_patch)

            for path, new_patch in new_patches:
                self.logger.info(f"Creating new patch {path} to preserve orthoganality")
                with open(path, "w") as f:
                    yaml.dump(new_patch, f)
                self.patches_to_test.append(path)

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
        #First, see if we dropped the number of network binds
        """
        if self.scores[run_index]["bound_sockets"] < self.scores[0]["bound_sockets"]:
            self.logger.info(f"Run {run_index} has fewer bound sockets than baseline. Not viable")
            return False
        """

        #Run 0 is always our baseline
        baseline = self.scores[0]["blocks_covered"]

        #Then, is overall health within 95% of the baseline?
        #our_score = sum(self.scores[run_index].values())
        our_score = self.scores[run_index]["blocks_covered"]
        self.logger.info(f"Blocks covered for {run_index}: {our_score} (baseline: {baseline}), difference: {100.0*our_score/baseline}%")
        return our_score >= 0.95 * baseline

    def get_best_patchset(self):
        """
        If we don't assume orthoganality, we have to run every combination of patches
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

        #Now, do the binary search. This is fairly optimistic, but can save a bunch of time when it works
        while self.run_count < self.max_iters and self.binary_search:
            self.logger.info(f"{len(self.patches_to_test)} patches remaining")
            self.logger.debug(f"Patches to test: {self.patches_to_test}")
            #This code is a little klugdy since we want to run three configs in parallel the first time
            #and two at a time after that
            if self.run_count == 0:
                first_half_index = self.run_count + 1
                second_half_index = self.run_count + 2
            else:
                first_half_index = self.run_count
                second_half_index = self.run_count + 1
            patchsets.append(self.patches_to_test[:len(self.patches_to_test)//2])
            patchsets.append(self.patches_to_test[len(self.patches_to_test)//2:])

            self.run_configs(patchsets)

            first_half = self.config_still_viable(first_half_index)
            second_half = self.config_still_viable(second_half_index)
            if first_half and second_half:
                self.logger.error("Config bisection had both halves pass. This is unexpected!!")
                self.logger.error("Moving to slow mode, it's possible you have overlapping patches")
                patchsets.clear()
                break
            elif not first_half and not second_half:
                self.logger.info("Config bisection had both halves fail. Time to move slowly")
                patchsets.clear()
                break
            elif first_half:
                self.logger.info("First half passed, second half failed. Considering first half")
                self.patches_to_test = deepcopy(self.runmap[first_half_index])
            else:
                self.logger.info("First half failed, second half passed. Considering second half")
                self.patches_to_test = deepcopy(self.runmap[second_half_index])

            patchsets.clear()
            if len(self.patches_to_test) == 1:
                self.logger.info("Only one patch left. Stopping")
                break

        if not self.binary_search:
            #If we skipped the binary search, we need to run the baseline
            self.run_configs([self.patches_to_test])

        #Assuming orthoganality of patches, we'll generate a config without each patch
        #Greater than 2 since if we have two left binary search would've tested them both
        if len(self.patches_to_test) > 2 or not self.binary_search:
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
                    self.logger.info(f"After running {i} removing {patch} from consideration, appears unecessary")
                    self.patches_to_test.remove(patch)
                    #Unless this was a set of redundant patches, then we'll take one of them

        output_file = os.path.join(self.proj_dir, "minimized.yaml")
        #TODO: force overwrite of this when --force
        if not os.path.exists(output_file):
            self.logger.info(f"Writing minimized config to {output_file} (note: this may include auto_explore.yaml)")
            patched_config = deepcopy(self.base_config)
            self.base_config["patches"].extend(self.patches_to_test)
            with open(output_file, "w") as f:
                yaml.dump(self.base_config, f)
        else:
            self.logger.info(f"Config already exists at {output_file}, not overwriting")
        return self.patches_to_test

def minimize(proj_dir, config_path, output_dir, timeout, max_iters=1000,
                 nworkers=1, verbose=False):
    pm = PatchMinmizer(proj_dir, config_path, output_dir, timeout, max_iters, nworkers, verbose)
    pm.run()
    print(f"{len(pm.patches_to_test)} required patches: {pm.patches_to_test}")
