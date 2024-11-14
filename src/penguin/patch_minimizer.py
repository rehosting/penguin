import os
import shutil
import csv
import re
import statistics, math
from time import sleep

from collections import Counter
from typing import List
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed

from penguin.common import getColoredLogger, yaml, frozenset_to_dict, dict_to_frozenset
from .penguin_config import dump_config, hash_yaml_config, load_config, load_unpatched_config
from .manager import PandaRunner, calculate_score

def calculate_entropy(buffer: bytes) -> float:
    # Count the frequency of each byte value
    byte_counts = Counter(buffer)
    total_bytes = len(buffer)

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy


VALID_TARGETS = ["webserver_start", "coverage", "network_traffic", "network_entropy"]

class PatchMinimizer():
    def __init__(self, proj_dir, config_path, output_dir, timeout,
                 max_iters, nworkers, verbose, minimization_target="webserver_start"):

        if minimization_target not in VALID_TARGETS:
            raise ValueError(f"Invalid minimization target {minimization_target}. Must be one of {VALID_TARGETS}")

        self.logger = getColoredLogger("penguin.patch_minmizer")
        self.proj_dir = (proj_dir + "/") if not proj_dir.endswith("/") else proj_dir
        self.output_dir = output_dir
        self.timeout = timeout
        self.max_iters = max_iters
        self.nworkers = nworkers
        self.verbose = verbose
        self.minimization_target = minimization_target
        self.patches_to_test = list()
        self.binary_search = True
        self.dynamic_patch_dir = os.path.join(self.proj_dir, "dynamic_patches")
        self.data_baseline = dict()

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

        # We have 3 patches to pick between: manual, single_shot, and auto_explore.
        # We never want manual. But we might want either single_shot or auto_explore depending on self.minimization_target
        # If we're set to www_start, we want to take single_shot, else we want auto_explore

        ignore_patches = ["manual"]
        required_patches = ["base", "lib_inject.core"]

        if self.minimization_target == "webserver_start":
            ignore_patches.extend(["auto_explore","single_shot"])
            this_required = "single_shot_ficd"
        else:
            ignore_patches.append("single_shot_ficd","single_shot")
            this_required = "auto_explore"

        required_patches.append(this_required)

        for patch in base_config["patches"]:
            if any(patch.endswith(f"{x}.yaml") for x in ignore_patches):
                self.logger.info(f"Ignoring {patch} to support automated minimization")

            if any(patch.endswith(f"/{x}.yaml") for x in required_patches):
                # Patches we just leave *always* enabled: base, auto_explore and lib_inject.core
                self.base_config["patches"].append(patch)
            else:
                # Patches we want to test. Will never include manual or single_shot (since we filtered at start of loop)
                self.patches_to_test.append(patch)

        # Ensure we have static_patches/auto_explore.yaml and NOT single_shot.yaml
        if not any([patch.endswith(f"/{this_required}.yaml") for patch in self.base_config["patches"]]):
            self.logger.warning(f"Adding {this_required} patch to supported automated exploration to guide minimization")
            # Ensure static_patches dir is in at least one of the patches
            assert (any([patch.startswith("static_patches") for patch in self.patches_to_test])), "No static_patches dir in patches - not sure how to add auto_explore"
            self.base_config["patches"].append(f"static_patches/{this_required}.yaml")

        #Patches can override options in previous patches
        #this can cause serious issues with our minimization algorithm since we assume patches are orthoganal
        self.original_patched_config = load_config(self.proj_dir, config_path)
        self.remove_shadowed_options()
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
                    sub_overlap = PatchMinimizer.dicts_overlap(dict1[key], dict2[key])
                    if sub_overlap:
                        overlap[key] = sub_overlap
                elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
                    sub_overlap = PatchMinimizer.lists_overlap(dict1[key], dict2[key])
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
                    sub_diff = PatchMinimizer.diff_dicts(dict1[key], dict2[key])
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

    @staticmethod
    def filter_conflicts(final_dict, patch, path=""):
        """
        Filter out any keys that are in the final_dict but with a different value

        This will need to get changed if patches start extending lists of instead of replacing them
        """
        filtered_patch = {}
        conflicts = []

        for key, value in patch.items():
            current_path = f"{path}.{key}" if path else key

            if key in final_dict:
                if isinstance(value, dict) and isinstance(final_dict[key], dict):
                    nested_filtered, nested_conflicts = PatchMinimizer.filter_conflicts(final_dict[key], value, current_path)
                    if nested_filtered:
                        filtered_patch[key] = nested_filtered
                    conflicts.extend(nested_conflicts)
                else:
                    if final_dict[key] != value:
                        conflicts.append((current_path, value, final_dict[key]))
                    else:
                        filtered_patch[key] = value
            else:
                filtered_patch[key] = value

        return filtered_patch, conflicts

    def remove_shadowed_options(self):
        """
        walk through each patch and remove any options that the unpatched config would overwrite
        we remove the old patch and generate a new one
        """
        for patch in deepcopy(self.patches_to_test):
            #load the patch
            with open(os.path.join(self.proj_dir, patch), "r") as f:
                loaded_patch = yaml.load(f, Loader=yaml.FullLoader)
            #get the differences between the patched and unpatched config
            new_patch, conflicts = self.__class__.filter_conflicts(self.original_patched_config, loaded_patch)

            if conflicts:
                self.patches_to_test.remove(patch)
                if new_patch:
                    os.makedirs(self.dynamic_patch_dir, exist_ok=True)
                    new_patch_path = os.path.join(self.dynamic_patch_dir,
                                                  f"unshadow_{patch.replace('/', '_')}_{hash_yaml_config(new_patch)[-6:]}.yaml")
                    with open(new_patch_path, "w") as f:
                        yaml.dump(new_patch, f)
                    self.patches_to_test.append(new_patch_path.replace(self.proj_dir, ""))
                    self.logger.info(f"Patch {patch} had options shadowed by final config, created a new patch without those options: {new_patch_path}")
                else:
                    self.logger.info(f"Patch {patch} had all options shadowed by final config, patch removed")
                self.logger.debug(f"conflicts were in the following options: {conflicts}")
            else:
                self.logger.info(f"Patch {patch} is free of options shadowed by final config")

    def split_overlapping_patches(self):
        """
        If we have overlapping patches, we attempt to preserve orthoganality by splitting them
        Ensuring that each unique configuration option is in only one patch
        However, in a real config only the last option is considered. So we should throw away 
        options that are not the last one.
        """
        overlapping = dict()
        for patch in self.patches_to_test:
            for other in self.patches_to_test:
                if patch != other:
                    patch_config = load_unpatched_config(os.path.join(self.proj_dir, patch))
                    other_config = load_unpatched_config(os.path.join(self.proj_dir, other))
                    overlap = PatchMinimizer.dicts_overlap(patch_config, other_config)
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
                diff = PatchMinimizer.diff_dicts(new_patch, frozenset_to_dict(overlap))

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
                self.patches_to_test.append(path.replace(self.proj_dir, ""))

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
        self.logger.info(f"Starting run {run_index} in {run_dir} with patches:\n\t" + "\n\t".join(patchset))

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
            raise

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
                    res = future.result()  # Optionally handle exceptions here
                    if res is None:
                        self.logger.error("Thread returned None??")
                        continue
                    index, score = res
                    if score is None:
                        # Error, need to retry. Add the patchset back to the queue
                        self.logger.error(f"Error running patchset {patchset}. Retrying")
                        self.patches_to_test.append(patchset)
                        continue
                    self.scores[index] = score
                except Exception as e:
                    print(f"Thread raised an exception: {e}")
                    self.logger.exception(e) # Show the full traceback
                    # Bail
                    executor.shutdown(wait=False)
                    break

    def calculate_network_data(self, run_index):
        '''
        From a directory, calculate the bytes sent, received, and entropy of received from the guest
        Consume vpn_{ip}_port files for data amounts (as csv) and vpn_response_{ip}_port files for entropy.
        Note that ip could be ipv6 with []s. Colons in names are replaced with underscores (weird for ipv6)
        '''

        output_dir = os.path.join(self.run_base, str(run_index), "output")
        total_data = dict()
        pattern = re.compile(r"vpn_(?:([0-9\.]+)|\[[0-9a-f]\]+)_(\d+)")
        pattern2 = re.compile(r"vpn_response_(?:([0-9\.]*)|\[[0-9a-f]\]).*_(\d+)")
        pattern3 = re.compile(r"web_(?:([0-9\.]*)|\[[0-9a-f]\]).*_(\d+)")

        if len(os.listdir(output_dir)) == 0:
            self.logger.error(f"Run {run_index} produced no output. This is unexpected")
            return

        if not os.path.isfile(os.path.join(output_dir, ".ran")):
            self.logger.error(f"Run {run_index} did not complete. This is unexpected")
            return

        default_data = {'to_guest':[], 'from_guest':[], 'entropy': 0.0, # Populated based on vpn logs
                        'first_length': 0, 'first_entropy': 0.0} # Populated based on fetch_web logs

        for file in os.listdir(output_dir):
            #and extract the port number:
            if m := pattern.match(file):
                # Looking at a log of data amounts
                sublist = ([], [])
                port = int(m.group(2))
                file_path = os.path.join(output_dir, file)
                with open(file_path, 'r', newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    for row in reader:
                        try:
                            sublist[0].append(int(row[0]))
                            sublist[1].append(int(row[1]))
                        except ValueError as e:
                            self.logger.error(f"Error reading {file_path}: {e}")
                            self.logger.error(f"Row: {row}")
                            continue
                if port not in total_data:
                    total_data[port] = deepcopy(default_data)
                total_data[port]['to_guest'].extend(sublist[0])
                total_data[port]['from_guest'].extend(sublist[1])

            elif m := pattern2.match(file):
                # Looking at a response file
                # Calculate the entropy of the response by reading the whole file
                port = int(m.group(2))
                if port not in total_data:
                    total_data[port] = deepcopy(default_data)

                file_path = os.path.join(output_dir, file)
                with open(file_path, "rb") as f:
                    entropy = calculate_entropy(f.read())
                self.logger.debug(f"Run {run_index} port {port} has entropy: {entropy:.02f}")
                total_data[port]['entropy'] = entropy
            elif m := pattern3.match(file):
                # Looking at fetch_web log
                port = int(m.group(2))
                if port not in total_data:
                    total_data[port] = deepcopy(default_data)
                # Populate length and update entropy
                with open(os.path.join(output_dir, file), "rb") as f:
                    data = f.read()
                    total_data[port]['first_entropy'] = calculate_entropy(data)
                    total_data[port]['first_length'] = len(data)

        return total_data

    def verify_net_traffic(self, run_index):
        '''
        Given the results of a run, determine if it's still viable based on network traffic as compared to the baseline
        '''
        assert(self.data_baseline), "Baseline data not established"
        target_ports = [80, 443]

        total_data = self.calculate_network_data(run_index)

        #Look at the bytes received from the guest
        for port, data in total_data.items():
            if len(target_ports) and port not in target_ports:
                continue # Skip non-target ports

            if port not in self.data_baseline.keys():
                self.logger.warning(f"On run {run_index}, port {port} produces traffic not seen in baseline. Ignoring")
                continue

            if self.data_baseline[port]['first_length'] == 0:
                #if we baseline didn't respond, we shouldn't expect one
                continue

            # IF ENTROPY - how does the entropy of the response compare to the baseline? We want it to be similar
            # First assert that the baseline has entropy
            if self.minimization_target == "network_entropy":
                assert 'entropy' in self.data_baseline[port], f"Baseline data for port {port} does not have entropy"
                if 'entropy' in data:
                    self.logger.info(f"Run {run_index} port {port} has entropy {data['entropy']:.02f}, baseline: {self.data_baseline[port]['entropy']:.02f}")
                    if data['entropy'] < 0.95 * self.data_baseline[port]['entropy']:
                        self.logger.info(f"Run {run_index} is not viable based on entropy of response on port {port}. Got {data['entropy']:.02f} vs baseline: {self.data_baseline[port]['entropy']:.02f}")
                        return False

            elif self.minimization_target == "network_traffic":
                # IF WEB - how does the mean bytes received from the guest compare to the baseline? We want it to be similar
                perc = 90
                port_percentile = PatchMinimizer.percentile(data['from_guest'], perc)
                baseline_percentile = PatchMinimizer.percentile(self.data_baseline[port]['from_guest'], perc)
                mean = statistics.mean(data['from_guest'])
                baseline_mean = statistics.mean(self.data_baseline[port]['from_guest'])
                self.logger.info(f"{perc}th percentile for port {port}: {port_percentile}, baseline: {baseline_percentile}")
                self.logger.info(f"mean for port {port}: {mean}, baseline: {baseline_mean}")
                if mean < 0.95 * baseline_mean:
                    self.logger.info(f"Run {run_index} is not viable based on mean bytes received from guest on port {port}")
                    return False

            elif self.minimization_target == "webserver_start":
                # We just want the webserver response to be non-empty
                if data['first_length'] == 0:
                    self.logger.info(f"Run {run_index} is not viable based on 0-byte first response length on port {port}")
                    return False
                self.logger.info(f"Run {run_index} has a non-empty first response on {port}: {data['first_length']} bytes with entropy {data['first_entropy']:.02f}")
            else:
                raise ValueError(f"Unknown minimization target {self.minimization_target}")
        return True

    def verify_coverage(self, run_index):
        '''
        Given the results of a run, determine if it's still viable based on coverage as compared to the baseline
        '''
        #First, see if we dropped the number of network binds
        if self.scores[run_index]["bound_sockets"] < self.scores[0]["bound_sockets"]:
            self.logger.info(f"Run {run_index} has fewer bound sockets than baseline. Not viable")
            return False

        #Run 0 is always our baseline
        baseline = self.scores[0]["blocks_covered"]

        #Then, is overall health within 95% of the baseline?
        #our_score = sum(self.scores[run_index].values())
        our_score = self.scores[run_index]["blocks_covered"]
        fraction_baseline = our_score / baseline
        self.logger.info(f"Blocks covered for {run_index}: {our_score} (baseline: {baseline}), our_score/baseline: {fraction_baseline}")
        if fraction_baseline > 1.10:
            self.logger.warning(f"Run {run_index} has more blocks >=10% more blocks covered than baseline. Are you sure baseline is optimized?")

        return fraction_baseline >= 0.95


    def verify_www_started(self, run_index):
        '''
        Check netbinds log to ensure we saw a webserver bind
        '''
        run_dir = os.path.join(self.run_base, str(run_index))

        with open(os.path.join(*[run_dir, "output", "netbinds_summary.csv"])) as f:
            reader = csv.DictReader(f)
            netbinds = [row for row in reader]
            www_start = any([row['bound_www'] == 'True' for row in netbinds])
            if not www_start:
                self.logger.info(f"Run {run_index} did not start a webserver. Not viable")
            return www_start

    def config_still_viable(self, run_index):
        '''
        Compare the results from this run to our baseline. Determine if it's still viable.
        If not, we return False, indicating that this config is not valid by our minimization target.
        '''
        failure = False

        if self.minimization_target == "webserver_start":
            # If no www start, it's not viable
            failure |= not self.verify_www_started(run_index)

        if not failure and self.minimization_target in ["webserver_start", "network_entropy", "network_traffic"]:
            # If we're doing network stuff, we need to check the network data
            failure |= not self.verify_net_traffic(run_index)

        if not failure and self.minimization_target == "coverage":
            failure |= self.verify_coverage(run_index)

        return not failure

    @staticmethod
    def percentile(data, percentile):
        data.sort()
        k = (len(data) - 1) * (percentile / 100)
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return data[int(k)]
        d0 = data[int(f)] * (c - k)
        d1 = data[int(c)] * (k - f)
        return d0 + d1

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

    def establish_baseline(self):
        '''
        For our very first run, we'll establish the baseline.

        First we'll validate that our provided config meets our expectations, or raise an exception if it fails
            IF minimization target is webserver_start:
                - it must already start a webserver - otherwise we can't minimize
            IF minimization target is coverage
                - it must produce coverage information (e.g., it should typically have auto_explore patch)
                - actual limitation: it should have the vpn, nmap, coverage plugins
            IF minimization target is network_traffic:
                - It must generate network traffic
                - actual requirements: should have the vpn and nmap plugins

        After validating the config, run the baseline and do an initial static minimization by removing any pseudofiles
        that aren't ever used. Split these into new patches and drop them from patches_to_test

        Finally, update self.patches_to_test
        '''

        # Check in self.original_patched_config that we have the necessary plugins

        match self.minimization_target:
            case 'coverage':
                # Check for the necessary plugins: vpn, nmap, coverage in self.original_patched_config['plugins'] keys
                required_plugins = ['vpn', 'nmap', 'coverage']
            case 'network_traffic':
                required_plugins = ['vpn', 'nmap']
            case 'network_entropy':
                required_plugins = ['vpn', 'nmap']
            case 'webserver_start':
                required_plugins = []

        for required_plugin in required_plugins:
            if required_plugin not in self.original_patched_config['plugins']:
                raise ValueError(f"Config does not have the required plugin: {required_plugin} for search mode {self.minimization_target}")

        if (self.minimization_target in ['network_traffic', 'network_entropy']) and not self.original_patched_config.get('plugins', {}).get('vpn', {}).get('log', False):
            raise ValueError(f"Config does not have plugins.vpn.log set, required for search mode {self.minimization_target}")

        assert(self.run_count == 0), f"Establish baseline should be run first not {self.run_count}"

        patchset = self.patches_to_test
        _, score = self.run_config(patchset, 0)
        self.run_count += 1 # Bump run_count so we don't re-run baseline

        # Score for baseline goes in self.scores (coverage) and data_baseline stores network data (entropy, bytes)
        self.scores[0] = score
        self.data_baseline = self.calculate_network_data(0)
        self.logger.debug(f"data_baseline: {self.data_baseline}")

        assert(self.data_baseline), "Baseline data not established"

        self.config_still_viable(0)

        # Output is in run_dir
        run_dir = os.path.join(self.run_base, "0")

        # Check netbinds_summary.csv to see if webserver (or other services start)
        with open(os.path.join(*[run_dir, "output", "netbinds_summary.csv"])) as f:
            reader = csv.DictReader(f)
            netbinds = [row for row in reader]
            www_start = any([row['bound_www'] == 'True' for row in netbinds])
            any_network_starts = len(netbinds) > 0

        if not any_network_starts:
            # No matter what you're doing, something should start a network service
            raise ValueError(f"Baseline config does not start any network services - invalid for mode {self.minimization_target}")

        if (self.minimization_target == 'webserver_start') and not www_start:
            # If you're minimizing on webserver start and your baseline doesn't start a webserver, that's a problem
            raise ValueError(f"Baseline config does not start a webserver - invalid for mode {self.minimization_target}")

        if (self.minimization_target in ['network_traffic', 'network_entropy']):
            if not self.data_baseline:
                # Check that baseline total_data isn't empty
                raise ValueError(f"Baseline config empty - no network traffic generated. Invalid for mode {self.minimization_target}")

            if not self.original_patched_config.get('plugins', {}).get('vpn', {}).get('log', False):
                # Network VPN must be enabled
                raise ValueError(f"Baseline config does not generate network traffic as plugins.vpn.log is not set - invalid for mode {self.minimization_target}")

            if sum([sum(data['from_guest']) for data in self.data_baseline.values()]) == 0:
                # Need network response
                raise ValueError(f"Baseline run had no network responses. Invalid for mode {self.minimization_target}")

            if self.minimization_target == 'network_entropy':
                # If data was non-zero I think entropy must also be non-zero - probably redundant
                if sum([data['entropy'] for data in self.data_baseline.values()]) == 0:
                    raise ValueError(f"Baseline run had no network entropy. Invalid for mode {self.minimization_target}")


        # Great - we have a valid baseline. Now let's figure out if any pseudofile patches are irrelevant.
        # Look at output/pseudofiles_modeled.yaml - the keys here are the pseudofiles that were modeled, everything else is irrelevant
        with open(os.path.join(*[run_dir, "output", "pseudofiles_modeled.yaml"])) as f:
            pseudofiles = yaml.safe_load(f)
            relevant_pseudofiles = set(pseudofiles.keys())

        # Now look at our patches providing pseudofiles. Split them into two groups: those that are relevant and aren't
        for patch in list(self.patches_to_test):
            with open(os.path.join(self.proj_dir, patch)) as f:
                patch_config = yaml.safe_load(f)
                pseudofiles = patch_config.get('pseudofiles', [])
                if not len(pseudofiles):
                    # No pseudofiles
                    continue

                # Does this contain any pseudofiles that *aren't* relevant?
                irrelevant_pseudofiles = set(pseudofiles) - relevant_pseudofiles
                if not len(irrelevant_pseudofiles):
                    # Everything was relevant
                    continue

                # We have irrelevant pseudofiles. Split them into a new (disabled) patch.
                # Split relevant ones into a new (enabled) patch. Drop the original patch

                # First create the new patch with only the relevant pseudofiles
                new_patch = deepcopy(patch_config)
                new_patch['pseudofiles'] = {pf: pseudofiles[pf] for pf in pseudofiles if pf not in irrelevant_pseudofiles}

                # Remove old patch from our queue
                self.patches_to_test.remove(patch)

                if len(new_patch['pseudofiles']) or len(new_patch.keys()) > 1:
                    # The new patch is doing something (either relevant pseudofiles or other actions)
                    os.makedirs(self.dynamic_patch_dir, exist_ok=True)
                    new_patch_path = os.path.join(self.dynamic_patch_dir, f"relevant_pseudofiles_{hash_yaml_config(new_patch)[-6:]}_{os.path.basename(patch)}")
                    with open(new_patch_path, "w") as f:
                        yaml.dump(new_patch, f)
                    self.patches_to_test.append(new_patch_path.replace(self.proj_dir, ""))
                    self.logger.info(f"Splitting patch {patch} into {new_patch_path} to remove {len(irrelevant_pseudofiles)} irrelevant pseudofiles")
                else:
                    self.logger.info(f"Removing patch {patch} entirely as it  only provides {len(irrelevant_pseudofiles)} irrelevant pseudofiles")


    def run(self):
        #First, establish a baseline score by running the base config.
        #We're going to do a binary search, so might as well run the other two halves as well

        #It is assumed by other code that run 0 is the baseline

        self.logger.info("Establishing baseline")
        self.establish_baseline()
        slow_mode = not self.binary_search

        patchsets=[] # Start with an empty list, we'll add our halves later

        #Now, do the binary search. This is fairly optimistic, but can save a bunch of time when it works
        if not slow_mode:
            while self.run_count < self.max_iters:
                self.logger.info(f"{len(self.patches_to_test)} patches remaining")
                self.logger.debug(f"Patches to test: {self.patches_to_test}")
                # XXX we used to special case the baseline as a 1-of-3 vs normally 1-of-2.
                # Now we just run the baseline before starting
                first_half_index = self.run_count
                second_half_index = self.run_count + 1
                patchsets.append(self.patches_to_test[:len(self.patches_to_test)//2])
                patchsets.append(self.patches_to_test[len(self.patches_to_test)//2:])

                self.run_configs(patchsets)

                #We need to record run 0's stats
                if not self.data_baseline:
                    raise ValueError("Baseline data not established")

                first_half = self.config_still_viable(first_half_index)
                second_half = self.config_still_viable(second_half_index)
                if first_half and second_half:
                    self.logger.warning("Config bisection had both halves pass. Either half is a valid solution? Testing in slow mode")
                    slow_mode = True
                    patchsets.clear()
                    break
                elif not first_half and not second_half:
                    self.logger.info("Config bisection had both halves fail. Time to move slowly")
                    slow_mode = True
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

        if slow_mode:
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
                        self.logger.info(f"After running {i} removing {patch} from consideration, appears unnecessary")
                        self.patches_to_test.remove(patch)
                    else:
                        self.logger.info(f"Keeping {patch} since run {i} was not viable without it")

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
    pm = PatchMinimizer(proj_dir, config_path, output_dir, timeout, max_iters, nworkers, verbose)
    pm.run()
    print(f"{len(pm.patches_to_test)} required patches: {pm.patches_to_test}")
