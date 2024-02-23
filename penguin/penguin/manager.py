import coloredlogs
import logging
import os
import select
import shutil
import subprocess
import time

import networkx as nx
import pandas as pd

from copy import deepcopy
from os import system
from random import choice
from threading import Thread, Lock
from typing import List, Tuple

from .common import yaml
from .penguin_prep import prepare_run
from .graphs import Configuration, ConfigurationManager, Failure, Configuration, Mitigation
from .utils import load_config, dump_config, hash_yaml_config, AtomicCounter, \
                    _load_penguin_analysis_from, get_mitigation_providers

coloredlogs.install(level='INFO', fmt='%(asctime)s %(name)s %(levelname)s %(message)s')

SCORE_CATEGORIES = ['execs', 'bound_sockets', 'devices_accessed', 'processes_run', 'modules_loaded',
                    'blocks_covered', 'nopanic', 'script_lines_covered']

logger = logging.getLogger('mgr')
logger.setLevel(logging.DEBUG)

# Cache output to avoid re-running previously seen configs.
# This is only useful in debugging where we'll rerun our scripts
# multiple times. In production we'll only run a search once per FW
# since nothing's configurable at runtime.
import glob
CACHE_SUPPORT = False
cache_dir = "/cache"
caches = {} # config hash -> output directory with .run.


class PandaRunner:
    '''
    This class is a gross wrapper around the fact that we want to call penguin_run
    in a subprocess because it might hang/crash (from C code) which would kill
    our python process. From this class we kill the subprocess if it takes too long
    (deadlock) or if it crashes.
    '''
    def __init__(self):
        pass

    def run(self, conf_yaml, run_base, run_dir, out_dir):
        # penguin_run will run panda directly which might exit (or crash/hang)
        # and definitely will close stdout/stderr which will break subsequent
        # python prints.
        # So we run it in an isolated process through penguin.penguin_run
        # which is a wrapper to call that script with: run_config(config=argv[1], out=argv[2], qcows=argv[3])

        # Let's call via system instead of subprocess
        data = yaml.safe_load(open(conf_yaml))
        timeout_s = None
        timeout_cmd = []
        if 'plugins' in data and 'core' in data['plugins'] and 'timeout' in data['plugins']['core']:
            # We'll give 3x run time to account for startup and shutdown processing time?
            timeout_s = data['plugins']['core']['timeout'] + 120 # First send singal 2 minutes after timeout
            timeout_ks = 120 # If signal is ignored, kill 2 minutes later
            timeout_cmd = ["timeout", "-s", "SIGUSR1", "-k", str(timeout_ks), str(timeout_s)]

        # SYSTEM() - not my favorite, but we need to kill the subprocess if it hangs.
        # Qemu output goes into out_dir/../qemu_std{out,err}.txt
        # Some initial python output will be returned in the system() call, so let's print it
        #full_cmd = f"{timeout_cmd}python3 -m penguin.penguin_run {conf_yaml} {out_dir} {run_base}/qcows"
        #print(system(full_cmd))

        # Python subprocess. No pipe (pipes can get full and deadlock the child!)
        cmd = timeout_cmd + ["python3", "-m", "penguin.penguin_run", conf_yaml, out_dir, f"{run_base}/qcows"]
        try:
            # This timeout is higher than our SIGUSR1 timeout so the guest can process the signal
            # Before the kill. We have a lot of timeouts...
            subprocess.run(cmd, timeout=timeout_s+180, check=True)
        except subprocess.TimeoutExpired:
            print(f"Timeout expired for {conf_yaml} after {timeout_s} seconds")
        except subprocess.CalledProcessError as e:
            print(f"Error running {conf_yaml}: {e}")

        ran_file = os.path.join(out_dir, ".ran")
        if not os.path.isfile(ran_file):
            logger.error(f"Missing .ran file with {conf_yaml}")
            raise RuntimeError(f"ERROR, running {conf_yaml} in {run_dir} did not produce {out_dir}/.ran file")

class Worker:
    def __init__(self, global_state, config_manager, run_base, max_iters, run_index, active_worker_count, thread_id=None):
        self.global_state = global_state
        self.config_manager = config_manager
        self.run_base = run_base
        self.max_iters = max_iters
        self.run_index = run_index
        self.active_worker_count = active_worker_count
        self.thread_id = thread_id

    def run(self):
        while self.max_iters == -1 or self.run_index.get() < self.max_iters:
            self.active_worker_count.increment()
            try:
                config = self.config_manager.run_exploration_cycle(self.run_config_f,
                                                                self.find_mitigations_f,
                                                                self.find_new_configs_f,
                                                                logger=logger)
            except Exception as e:
                logger.error(f"Error in run_exploration_cycle: {e}")
                raise e
            finally:
                self.active_worker_count.decrement()

            if config is None:
                time.sleep(1)
                # If all workers are waiting, that means we're done
                if self.active_worker_count.get() == 0:
                    logger.info("All workers waiting, exiting")
                    return
                else:
                    logger.info(f"Worker got no work, but {self.active_worker_count.get()} workers still active. Stalling")

    def find_new_configs_f(self, failure : Failure, mitigation : Mitigation, parent_config : Configuration) -> List[Configuration]:
        '''
        Given a failure and mitigation, find new configurations to explore
        '''

        providers = get_mitigation_providers(parent_config.info)

        if failure.type not in providers:
            logger.warning(f"No mitigation provider for {failure.id} - ignoring")
            return []

        results = []

        #print(f"Asking {failure.type} to mitigate {failure} with {mitigation}")
        # XXX: would this ever want to return more than one config? For now it's a list...
        for c in providers[failure.type].implement_mitigation(parent_config, failure, mitigation) or []:
            #print(f"Plugin {failure.type} suggests config {c}")
            if not isinstance(c, Configuration):
                raise TypeError(f"Plugin {failure.type} returned a non-Configuration object {c}")

            # If the mitigation has the 'exclusive' property AND already has a child, we skip?
            #if mitigation.exclusive and len(self.config_manager.graph.descendants(mitigation.gid)):
            #    print(f"Skipping {c} as {mitigation} is exclusive and previously used")
            #    continue

            results.append(c)

        return results

    def find_mitigations_f(self, failure : Failure, config : Configuration) -> List[Mitigation]:
        results = []
        # Lookup the plugin that can handle this failure
        analysis = get_mitigation_providers(config.info)[failure.type]
        #print(f"Get potential mitigation for {failure} from {analysis}")
        for m in analysis.get_potential_mitigations(config.info, failure) or []:
            if not isinstance(m, Mitigation):
                raise TypeError(f"Plugin {analysis.ANALYSIS_TYPE} returned a non-Mitigation object {m}")
            #this_logger = logging.getLogger(f"mgr{self.thread_id if self.thread_id is not None else ''}.run.{self.run_idx}")
            #this_logger.info(f"Plugin {analysis.ANALYSIS_TYPE} suggests mitigation {m}")
            results.append(m)
        return results

    def run_config_f(self, config : Configuration) -> Tuple[List[Failure], float]:
        '''
        Run a given configuration, collect details of it's failures and calculate score
        '''
        self.run_idx = self.run_index.increment()
        run_dir = os.path.join(self.run_base, str(self.run_idx))
        if os.path.isdir(run_dir):
            # Remove it
            shutil.rmtree(run_dir)
        os.makedirs(run_dir)

        # Write config to disk
        combined_config = deepcopy(config.info)
        combined_config['core'] = self.global_state.info
        dump_config(combined_config, os.path.join(run_dir, "config.yaml"))

        # Dump string representation of graph
        with open(os.path.join(run_dir, "graph.txt"), "w") as f:
            f.write(self.config_manager.stringify_state())

        with open(os.path.join(run_dir, "full_graph.txt"), "w") as f:
            f.write(self.config_manager.stringify_state2())

        # Log info
        this_logger = logging.getLogger(f"mgr{self.thread_id if self.thread_id is not None else ''}.run.{self.run_idx}")

        if parent_cc := self.config_manager.graph.get_parent_config(config):
            parent_failure = self.config_manager.graph.get_parent_failure(config)
            parent_mitigation = self.config_manager.graph.get_parent_mitigation(config)
            this_logger.debug(f"Derived from {parent_cc} with {parent_mitigation} to fix {parent_failure}")
            # Record parent in output directory:
            with open(os.path.join(run_dir, "parent.txt"), "w") as f:
                f.write(f"parent={parent_cc.run_idx}\n")
        else:
            this_logger.debug(f"Root config")

        # DEBUG: save graph to disk
        #if len(self.config_manager.graph.graph.nodes) < 50:
        #    self.config_manager.graph.create_png(os.path.join(run_dir, "graph.png"))

        # Dump pickle of graph every 5
        #if self.run_idx % 5 == 0:
        #    self.config_manager.graph.save_graph(os.path.join(run_dir, "graph.pkl"))

        # *** EMULATE TARGET ***
        # Run emulation `n_config_tests` times
        n_config_tests = 1

        conf_yaml = os.path.join(run_dir, "config.yaml")
        do_run = True
        if CACHE_SUPPORT:
            # We have cache support. Hash our *whole config* and see if it's in the global cache
            # If so, set out_dir to that and skip run. Otherwise do run. XXX: Not hash_yaml_config
            # because that ignores the core section
            data = yaml.safe_load(open(conf_yaml))
            config_hash = hash_yaml_config(data)
            if config_hash in caches:
                # Copy the cache directory to our run_dir
                # Only works for n_config_tests = 1
                assert(n_config_tests == 1), f"{n_config_tests} != 1: Unsupported"

                # Check if we have a .ran file in the cache directory and .config
                if os.path.isfile(os.path.join(*[caches[config_hash], "output", ".ran"])) and \
                        os.path.isfile(os.path.join(caches[config_hash], "config.yaml")):
                    #print(f"Cache hit for {config_hash}")
                    do_run = False
                    shutil.copytree(os.path.join(caches[config_hash], 'output'), os.path.join(run_dir, 'output'))
                else:
                    print(f"\tInvalid cache hit {config_hash} - ignore")
                    # Delete the cache entry
                    shutil.rmtree(caches[config_hash])

        if do_run:
            for config_idx in range(n_config_tests):
                out_dir = os.path.join(run_dir, "output" + (str(config_idx) if config_idx > 0 else ""))
                os.makedirs(out_dir, exist_ok=True)
                try:
                    #self._subprocess_panda_run(conf_yaml, run_dir, out_dir)
                    PandaRunner().run(conf_yaml, self.run_base, run_dir, out_dir)
                except RuntimeError as e:
                    # Uh oh, we got an error while running. Warn and continue
                    this_logger.error(f"Could not run {run_dir}: {e}")
                    return [], 0, None

            if CACHE_SUPPORT:
                # We had a cache miss. Add this config into hash
                if os.path.isfile(os.path.join(run_dir, "output", ".ran")):
                    this_cache_dir = os.path.join(cache_dir, config_hash)
                    if os.path.isdir(this_cache_dir):
                        print(f"ERROR: Cache directory already exists, this should never happen. {run_dir} has hash {config_hash}")
                    else:
                        shutil.copytree(run_dir, this_cache_dir)
                        caches[config_hash] = this_cache_dir
                else:
                    print(f"Not caching config as it did not produce a .ran file")

        # if we have an exclusive config, treat score as 0
        scores = self.find_best_score(run_dir, self.run_idx, n_config_tests, config.exclusive is not None, this_logger)

        failures = self.analyze_failures(run_dir, config, n_config_tests, this_logger)

        # Record details of failures into output directory
        # Failures are a list of Failure objects. Above output dir because it's not a part of
        # our real dynamic analysis, more meta-info
        with open(os.path.join(run_dir, "failures.yaml"), "w") as f:
            yaml.dump([fail.to_dict() for fail in failures], f)

        # Dump string representation of graph after
        with open(os.path.join(run_dir, "graph_after.txt"), "w") as f:
            f.write(self.config_manager.stringify_state())

        # XXX Better score aggregation? Can we use dynamic weights or something?
        return failures, sum(scores.values()), self.run_idx

    def find_best_score(self, run_dir, run_idx, n_config_tests, is_exclusive, this_logger):
        '''
        Look acrous our `n_config_tests` runs. Calculate the maximal score for each
        score type our various metrics. Note n_config_tests is 1 for now. Later
        we might increase depending on expected non-determinism.
        '''
        best_scores = {} # For each key, maximal score across all runs
        for config_idx in range(n_config_tests):
            these_scores = self.calculate_score(os.path.join(run_dir, f"output{config_idx}" if config_idx > 0 else "output"))
            for score_name, score in these_scores.items():
                if score_name not in best_scores or score > best_scores[score_name]:
                    best_scores[score_name] = score

        if is_exclusive:
            # Exclusive configs get a fixed score of 0, they're an intermediate analysis
            best_scores = {k: 0 for k in best_scores}

        # Report scores and save to disk
        #this_logger.info(f"scores: {[f'{k[:4]}:{v}' for k, v in best_scores.items()]}")
        with open(os.path.join(run_dir, "scores.txt"), "w") as f:
            f.write("score_type,score\n")

            for k, v in best_scores.items():
                f.write(f"{k},{v:.02f}\n")

        # Write a single score to disk
        with open(os.path.join(run_dir, "score.txt"), "w") as f:
            total_score = sum(best_scores.values())
            f.write(f"{total_score:.02f}")

        return best_scores

    def analyze_failures(self, run_dir, node, n_config_tests, this_logger):
        '''
        After we run a configuration, do our post-run analysis of failures.
        Run each PyPlugin that has a PenguinAnalysis implemented. Have each
        identify failures.
        '''

        fails = [] # (id, type, {data})
        for config_idx in range(n_config_tests):
            output_dir = os.path.join(run_dir, f"output{config_idx}" if config_idx > 0 else "output")

            mitigation_providers = get_mitigation_providers(node.info)

            # For an exclusive config, only query the exclusive provider
            if node.exclusive is not None:
                if node.exclusive not in mitigation_providers:
                    raise ValueError(f"Cannot use exclusive {node.info['exclusive']} as it's not a mitigation provider")
                mitigation_providers = {node.exclusive: mitigation_providers[node.exclusive]}

            for plugin_name, analysis in mitigation_providers.items():
                try:
                    failures = analysis.parse_failures(output_dir)
                except Exception as e:
                    this_logger.error(e)
                    raise e

                #if len(failures):
                    #this_logger.info(f"Plugin {plugin_name} reports {len(failures)} failures: {failures}")

                for failure in (failures or []):
                    if not isinstance(failure, Failure):
                        raise TypeError(f"Plugin {plugin_name} returned a non-Failure object {failure}")
                    fails.append(failure)

        # We might have duplicate failures, but that's okay, caller will dedup?
        return fails

    def calculate_score(self, result_dir):
        '''
        Return a dict of the distinct metrics we care about name: value
        XXX should have a global of how many fields this is

        XXX: We should call into our loaded plugins to calculate
        this score metric! Plugins could raise a fatal error
        or return a dict with names and values
        '''
        if not os.path.isfile(os.path.join(result_dir, ".ran")):
            raise RuntimeError(f"calculate_score: {result_dir} does not have a .ran file - check logs for error")

        # System Health: execs, sockets, devices
        with open(f"{result_dir}/health_final.yaml") as f:
            health_data = yaml.safe_load(f)

        # Panic or not (inverted so we can maximize)
        panic = False

        # We can only read console output if it's saved to disk
        # (instead of being shown on stdout)
        if not self.global_state.info['show_output']:
            with open(f"{result_dir}/console.log", 'r', encoding='utf-8', errors='ignore') as f:
                for line in f.readlines():
                    if "Kernel panic" in line:
                        panic = True
                        break

        # Shell cov: number of lines (minus one) in shell_cov.csv
        with open(f"{result_dir}/shell_cov.csv") as f:
            shell_cov = len(f.readlines()) - 1

        # Coverage: processes, modules, blocks
        if os.path.isfile(f"{result_dir}/coverage.csv"):
            with open(f"{result_dir}/coverage.csv") as f:
                # xxx no header, but it's process, module, offset. no index either
                df = pd.read_csv(f, header=None, names=['process', 'module', 'offset'], index_col=False)
            processes_run = df['process'].nunique()
            modules_loaded =  df['module'].nunique()
            blocks_covered = df.drop_duplicates(subset=['module', 'offset']).shape[0] # Count of unique (module, offset) pairs
        else:
            print(f"WARNING: No coverage.csv found in {result_dir}")
            processes_run = 0
            modules_loaded = 0
            blocks_covered = 0


        score = {
            'execs': health_data['nexecs'],
            'bound_sockets': health_data['nbound_sockets'],
            'devices_accessed': health_data['nuniquedevs'],
            'processes_run': processes_run,
            'modules_loaded': modules_loaded,
            'blocks_covered': blocks_covered,
            'script_lines_covered': shell_cov,
            'nopanic': 1 if not panic else 0,
        }

        for k in score.keys():
            if k not in SCORE_CATEGORIES:
                raise ValueError(f"BUG: score type {k} is unknown")
        return score


class GlobalState:
    def __init__(self, output_dir, base_config):
        # show_output is False unless we're told otherwise
        show_output = base_config['core']['show_output'] \
            if 'show_output' in base_config['core'] else False

        # root_shell is True unless we're told otherwise
        root_shell = base_config['core']['root_shell'] \
                if 'root_shell' in base_config['core'] else True

        self.info = {
            'arch': base_config['core']['arch'],
            'fs': base_config['core']['fs'],
            'kernel': base_config['core']['kernel'],
            'qcow': base_config['core']['qcow'],
            'show_output': show_output,
            'root_shell': root_shell,
            'version': '1.0.0'
        }
        del base_config['core'] # Nobody should use base, ask us instead!
        if not os.path.isfile(self.info['fs']):
            raise ValueError(f"Base filesystem archive not found: {self.info['fs']}")

        # Static analysis *must* have found some inits, otherwise we can't even start execution!
        # Potential inits will be in our base directory, should be in output_dir, I think?
        self.inits = []
        # Read from output_dir/base/env.yaml to get inits
        with open(os.path.join(output_dir, "base", "env.yaml")) as f:
            env = yaml.safe_load(f)
            for k, v in env.items():
                if k == 'igloo_init':
                    self.inits.extend(v)

        if not self.inits:
            raise RuntimeError(f"No potential inits found in {output_dir}/base/env.yaml")

def add_init_options_to_graph(config_manager, global_state, base_config):
    '''
    A config needs to have an ['env']['igloo_init'] in order to do anything useful.
    We might have a single option already set or we might have multiple options
    stored in our global_state (based on static analysis).

    If we have no value set and no potential values, we raise an error.

    Otherwise we'll create a fake failure for "init" and a mitigation
    node to add each of the init options. Then we'll create configs
    with each init and add the necessary graph edges. This means
    we'll start our search with multiple configuration options (nodes)
    to explore.

    If an igloo_init is set in the initial config, we'll assume that's
    right and leave it alone.
    '''
    # Hack igloo_inits into graph as a failure and mitigation.
    # But only if we don't have igloo_init set and have multiple
    # potential values
    if len(base_config.info['env'].get('igloo_init', [])) == 0:
        if len(global_state.inits) == 0:
            raise RuntimeError(f"No potential init binaries identified and none could be found")

        base = config_manager.graph.get_node(base_config.gid)
        assert(base is not None), f"BUG: base config {base_config} not in configuration"
        if base.run:
            raise RuntimeError(f"Base config {base_config} already ran, cannot add init options")
        base.run = True

        # Add a fake failure
        init_fail = Failure("init", "init", {"inits": global_state.inits})
        config_manager.graph.add_node(init_fail)
        # Connect back to baseline
        config_manager.graph.add_edge(base_config, init_fail)

        # Now for each, add mitigations and new config
        for init in global_state.inits:
            # First add mitigation:
            this_init_mit = Mitigation(f"init_{init}", "init", {"init": init})
            config_manager.graph.add_node(this_init_mit)

            # Connect failure to mitigation
            config_manager.graph.add_edge(init_fail, this_init_mit, unknown=True)

            # Next add new config
            conf_info = deepcopy(base_config.info)
            conf_info['env']['igloo_init'] = init
            new_config = Configuration(init, conf_info)
            config_manager.graph.add_node(new_config)

            # Connect new config to mitigation and parent config
            config_manager.graph.add_edge(base_config, new_config, delta=f"init={init}")
            config_manager.graph.add_edge(this_init_mit, new_config)


def graph_search(initial_config, output_dir, max_iters=1000, nthreads=1):
    '''
    Main entrypoint. Given an initial config and directory run our
    graph search.
    '''

    run_index = AtomicCounter(0)
    active_worker_count = AtomicCounter(0)

    run_base = os.path.join(output_dir, "runs")
    os.makedirs(run_base, exist_ok=True)

    base_config = Configuration("baseline", initial_config)
    config_manager = ConfigurationManager(base_config)
    global_state = GlobalState(output_dir, base_config.info)

    # We created a config node with our initial config as .info
    # Let's see if we can find it?
    #assert(config_manager.graph.get_existing_node(base_config.info) is not None)

    # Add various init binaries to graph
    add_init_options_to_graph(config_manager, global_state, base_config)

    if CACHE_SUPPORT:
        # Find all configs in cache_dir and hash them. Store hashes in
        # caches dict. Whenever we try running a config, check if it's
        # in caches. If so, copy that directory to our run_base and
        # skip running it.
        for f in glob.glob(f"{cache_dir}/*/config.yaml"):
            # Load yaml file from f
            data = yaml.safe_load(open(f))
            config_hash = hash_yaml_config(data)
            caches[config_hash] = os.path.dirname(f)

    worker_threads = []
    if nthreads > 1:
        for idx in range(nthreads):
            worker_instance = Worker(global_state, config_manager,
                                        run_base, max_iters, run_index,
                                        active_worker_count, thread_id=idx)
            t = Thread(target=worker_instance.run)
            t.start()
            worker_threads.append(t)

        # Wait for all threads to finish
        for t in worker_threads:
            t.join()
    else:
        # Single thread mode, try avoiding deadlocks by just running directly
        Worker(global_state, config_manager, run_base, max_iters,
            run_index, active_worker_count).run()

    # We're all done! In the .finished file we'll write the final run_index
    # This way we can tell if a run is done early vs still in progress
    with open(os.path.join(output_dir, "finished.txt"), "w") as f:
        f.write(str(run_index.get()))

def main():
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <config> <outdir>")
        sys.exit(1)

    config = load_config(sys.argv[1])
    graph_search(config, sys.argv[2])

if __name__ == '__main__':
    main()
