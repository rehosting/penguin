import time
import shutil
import glob
import os
import csv
from threading import Thread
from typing import List, Tuple
from copy import deepcopy

from penguin import getColoredLogger
from .common import yaml, get_inits_from_proj
from .graphs import Configuration, ConfigurationManager, Failure, Mitigation
from .penguin_config.structure import dump_config, hash_yaml_config, load_config
from .utils import AtomicCounter, get_mitigation_providers
from .manager import PandaRunner, calculate_score

WWW_ONLY = False  # To simplify large scale evaluations - should we bail early if we see a webserver start?

# Cache output to avoid re-running previously seen configs.
# This is only useful in debugging where we'll rerun our scripts
# multiple times. In production we'll only run a search once per FW
# since nothing's configurable at runtime.
CACHE_SUPPORT = False
cache_dir = "/cache"
caches = {}  # config hash -> output directory with .run.



class Worker:
    def __init__(
        self,
        global_state,
        config_manager,
        proj_dir,
        run_base,
        max_iters,
        run_index,
        timeout,
        active_worker_count,
        verbose=False,
        thread_id=None,
        logger=None,
    ):
        self.global_state = global_state
        self.config_manager = config_manager
        self.proj_dir = proj_dir
        self.run_base = run_base
        self.max_iters = max_iters
        self.run_index = run_index
        self.active_worker_count = active_worker_count
        self.thread_id = thread_id
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logger or getColoredLogger(
            f"mgr{self.thread_id if self.thread_id is not None else ''}.run.{self.run_index.get()}"
        )

    def run(self):
        while self.max_iters == -1 or self.run_index.get() < self.max_iters:
            self.active_worker_count.increment()
            try:
                config = self.config_manager.run_exploration_cycle(
                    self.run_config_f,
                    self.find_mitigations_f,
                    self.find_new_configs_f,
                    logger=self.logger,
                )
            except Exception as e:
                self.logger.error(f"Error in run_exploration_cycle: {e}")
                raise e
            finally:
                self.active_worker_count.decrement()

            if config is None:
                time.sleep(1)
                # If all workers are waiting, that means we're done
                if self.active_worker_count.get() == 0:
                    self.logger.info("All workers waiting, exiting")
                    return

    def find_new_configs_f(
        self, failure: Failure, mitigation: Mitigation, parent_config: Configuration
    ) -> List[Configuration]:
        """
        Given a failure and mitigation, find new configurations to explore
        """

        providers = get_mitigation_providers(parent_config.info)

        if failure.type not in providers:
            self.logger.warning(f"No mitigation provider for {failure.id} - ignoring")
            return []

        results = []

        # print(f"Asking {failure.type} to mitigate {failure} with {mitigation}")
        # XXX: would this ever want to return more than one config? For now it's a list...
        for c in (
            providers[failure.type].implement_mitigation(
                parent_config, failure, mitigation
            )
            or []
        ):
            if not isinstance(c, Configuration):
                raise TypeError(
                    f"Plugin {failure.type} returned a non-Configuration object {c}"
                )

            if c == parent_config:
                self.logger.error(
                    f"Plugin {failure.type} returned the parent config {c} as a new config Ignoring"
                )
                continue

            # If the mitigation has the 'exclusive' property AND already has a child, we skip?
            # if mitigation.exclusive and len(self.config_manager.graph.descendants(mitigation.gid)):
            #    print(f"Skipping {c} as {mitigation} is exclusive and previously used")
            #    continue

            results.append(c)

        return results

    def find_mitigations_f(
        self, failure: Failure, config: Configuration
    ) -> List[Mitigation]:
        results = []
        # Lookup the plugin that can handle this failure
        analysis = get_mitigation_providers(config.info)[failure.type]
        # print(f"Get potential mitigation for {failure} from {analysis}")
        for m in analysis.get_potential_mitigations(config.info, failure) or []:
            if not isinstance(m, Mitigation):
                raise TypeError(
                    f"Plugin {analysis.ANALYSIS_TYPE} returned a non-Mitigation object {m}"
                )
            # self.logger.info(f"Plugin {analysis.ANALYSIS_TYPE} suggests mitigation {m}")
            results.append(m)
        return results

    def run_config_f(self, config: Configuration) -> Tuple[List[Failure], float]:
        """
        Run a given configuration, collect details of it's failures and calculate score
        """
        self.run_idx = self.run_index.increment()
        run_dir = os.path.join(self.run_base, str(self.run_idx))
        if os.path.isdir(run_dir):
            # Remove it
            shutil.rmtree(run_dir)
        os.makedirs(run_dir)

        # Write config to disk
        combined_config = deepcopy(config.info)
        combined_config["core"] = self.global_state.info
        dump_config(combined_config, os.path.join(run_dir, "config.yaml"))

        # Dump string representation of graph
        with open(os.path.join(run_dir, "graph.txt"), "w") as f:
            f.write(self.config_manager.stringify_state())

        with open(os.path.join(run_dir, "full_graph.txt"), "w") as f:
            f.write(self.config_manager.stringify_state2())

        if parent_cc := self.config_manager.graph.get_parent_config(config):
            parent_failure = self.config_manager.graph.get_parent_failure(config)
            parent_mitigation = self.config_manager.graph.get_parent_mitigation(config)
            self.logger.debug(
                f"Derived from {parent_cc} with {parent_mitigation} to fix {parent_failure}"
            )
            # Record parent in output directory:
            with open(os.path.join(run_dir, "parent.txt"), "w") as f:
                f.write(f"parent={parent_cc.run_idx}\n")
            with open(os.path.join(run_dir, "parent_mitigation.txt"), "w") as f:
                f.write(f"{parent_mitigation.type}\n")
                f.write(f"{parent_mitigation.exclusive}\n")
                f.write(f"{parent_mitigation.info}\n")
        else:
            self.logger.debug("Root config")

        # DEBUG: save graph to disk
        # if len(self.config_manager.graph.graph.nodes) < 50:
        #    self.config_manager.graph.create_png(os.path.join(run_dir, "graph.png"))

        # Dump pickle of graph every 5
        # if self.run_idx % 5 == 0:
        #    self.config_manager.graph.save_graph(os.path.join(run_dir, "graph.pkl"))

        # *** EMULATE TARGET ***
        # Run emulation `n_config_tests` times
        n_config_tests = 1

        truncated = 0  # How much did we shorten the execution by (as an optimization)
        # Number of sections less than our allowed timeout

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
                assert n_config_tests == 1, f"{n_config_tests} != 1: Unsupported"

                # Check if we have a .ran file in the cache directory and .config
                if os.path.isfile(
                    os.path.join(*[caches[config_hash], "output", ".ran"])
                ) and os.path.isfile(os.path.join(caches[config_hash], "config.yaml")):
                    # print(f"Cache hit for {config_hash}")
                    do_run = False
                    shutil.copytree(
                        os.path.join(caches[config_hash], "output"),
                        os.path.join(run_dir, "output"),
                    )
                else:
                    print(f"\tInvalid cache hit {config_hash} - ignore")
                    # Delete the cache entry
                    shutil.rmtree(caches[config_hash])

        if do_run:
            # config_depth = self.config_manager.graph.get_config_depth(config)
            for config_idx in range(n_config_tests):
                out_dir = os.path.join(
                    run_dir, "output" + (str(config_idx) if config_idx > 0 else "")
                )
                os.makedirs(out_dir, exist_ok=True)
                try:
                    # self._subprocess_panda_run(conf_yaml, run_dir, out_dir)
                    PandaRunner().run(
                        conf_yaml, self.proj_dir, out_dir,
                        timeout=self.timeout, verbose=self.verbose
                    )

                except RuntimeError as e:
                    # Uh oh, we got an error while running. Warn and continue
                    self.logger.error(f"Could not run {run_dir}: {e}")
                    return [], 0, None

            if CACHE_SUPPORT:
                # We had a cache miss. Add this config into hash
                if os.path.isfile(os.path.join(run_dir, "output", ".ran")):
                    this_cache_dir = os.path.join(cache_dir, config_hash)
                    if os.path.isdir(this_cache_dir):
                        print(
                            f"ERROR: Cache directory already exists, this should never happen. {run_dir} has hash {config_hash}"
                        )
                    else:
                        shutil.copytree(run_dir, this_cache_dir)
                        caches[config_hash] = this_cache_dir
                else:
                    print("Not caching config as it did not produce a .ran file")

        # if we have an exclusive config, treat score as 0
        scores = self.find_best_score(
            run_dir, self.run_idx, n_config_tests, config.exclusive is not None
        )

        failures = self.analyze_failures(run_dir, config, n_config_tests, logger=self.logger)

        if not len(failures) and truncated > 0:
            # We saw no failures, but we also were running with a shortened execution. Make a fake failure that
            # We'll mitigate in core
            failures.append(Failure("truncation", "core", {"truncated": truncated}))

        # Record details of failures into output directory
        # Failures are a list of Failure objects. Above output dir because it's not a part of
        # our real dynamic analysis, more meta-info
        with open(os.path.join(run_dir, "failures.yaml"), "w") as f:
            yaml.dump([fail.to_dict() for fail in failures], f)

        # XXX Better score aggregation? Can we use dynamic weights or something?
        final_score = sum(scores.values())
        # Compare to parent score, if we had a parent
        if parent_cc:
            parent_score = parent_cc.health_score
            with open(os.path.join(run_dir, "score_delta.txt"), "w") as f:
                f.write(f"{final_score-parent_score:.02f}")

        # Config option to bail after we first see a webserver start
        if WWW_ONLY:
            # Check if netbinds.csv contains a bind for port 80. If so we'll terminate early
            # If this config was non-exclusive (i.e., it was a normal run, no symex/dynval), we're done!
            if not config.exclusive and os.path.isfile(
                os.path.join(run_dir, "output", "netbinds.csv")
            ):
                with open(os.path.join(run_dir, "output", "netbinds.csv"), "r") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row["guest_port"] == "80":
                            self.logger.info(
                                f"Terminating early due to port 80 bind in {run_dir}"
                            )
                            for _ in range(self.max_iters):
                                self.run_index.increment()  # There must be a better way to do this
                            break

        return failures, final_score, self.run_idx

    def find_best_score(self, run_dir, run_idx, n_config_tests, is_exclusive):
        """
        Look acrous our `n_config_tests` runs. Calculate the maximal score for each
        score type our various metrics. Note n_config_tests is 1 for now. Later
        we might increase depending on expected non-determinism.
        """
        best_scores = {}  # For each key, maximal score across all runs
        for config_idx in range(n_config_tests):
            these_scores = calculate_score(
                os.path.join(
                    run_dir, f"output{config_idx}" if config_idx > 0 else "output"
                ),
                have_console=not self.global_state.info["show_output"],
            )
            for score_name, score in these_scores.items():
                if score_name not in best_scores or score > best_scores[score_name]:
                    best_scores[score_name] = score

        if is_exclusive:
            # Exclusive configs get a fixed score of 0, they're an intermediate analysis
            best_scores = {k: 0 for k in best_scores}

        # Report scores and save to disk
        # self.logger.info(f"scores: {[f'{k[:4]}:{v}' for k, v in best_scores.items()]}")
        with open(os.path.join(run_dir, "scores.txt"), "w") as f:
            f.write("score_type,score\n")

            for k, v in best_scores.items():
                f.write(f"{k},{v:.02f}\n")

        # Write a single score to disk
        with open(os.path.join(run_dir, "score.txt"), "w") as f:
            total_score = sum(best_scores.values())
            f.write(f"{total_score:.02f}\n")

        return best_scores

    @staticmethod
    def analyze_failures(run_dir, node, n_config_tests, logger=None):
        """
        After we run a configuration, do our post-run analysis of failures.
        Run each PyPlugin that has a PenguinAnalysis implemented. Have each
        identify failures.

        Staticmethod with logger arg so we can call from other search algos too. Maybe
        worth refactoring into manager or something more generic?
        """

        fails = []  # (id, type, {data})
        for config_idx in range(n_config_tests):
            output_dir = os.path.join(
                run_dir, f"output{config_idx}" if config_idx > 0 else "output"
            )

            mitigation_providers = get_mitigation_providers(node.info)

            # For an exclusive config, only query the exclusive provider
            if node.exclusive is not None:
                if node.exclusive not in mitigation_providers:
                    raise ValueError(
                        f"Cannot use exclusive {node.info['exclusive']} as it's not a mitigation provider"
                    )
                mitigation_providers = {
                    node.exclusive: mitigation_providers[node.exclusive]
                }

            for plugin_name, analysis in mitigation_providers.items():
                try:
                    failures = analysis.parse_failures(output_dir)
                except Exception as e:
                    logger.error(e)
                    raise e

                # if len(failures):
                # logger.info(f"Plugin {plugin_name} reports {len(failures)} failures: {failures}")

                for failure in failures or []:
                    if not isinstance(failure, Failure):
                        raise TypeError(
                            f"Plugin {plugin_name} returned a non-Failure object {failure}"
                        )
                    fails.append(failure)

        # We might have duplicate failures, but that's okay, caller will dedup?
        return fails


class GlobalState:
    def __init__(self, proj_dir, output_dir, base_config):
        self.proj_dir = proj_dir
        # show_output is False unless we're told otherwise
        show_output = (
            base_config["core"]["show_output"]
            if "show_output" in base_config["core"]
            else False
        )

        # root_shell is True unless we're told otherwise
        root_shell = (
            base_config["core"]["root_shell"]
            if "root_shell" in base_config["core"]
            else True
        )

        self.info = {
            "arch": base_config["core"]["arch"],
            "fs": base_config["core"]["fs"],
            "kernel": base_config["core"]["kernel"],
            "show_output": show_output,
            "root_shell": root_shell,
            "version": base_config["core"]["version"],
        }
        del base_config["core"]  # Nobody should use base, ask us instead!
        if not os.path.isfile(os.path.join(proj_dir, self.info["fs"])):
            raise ValueError(f"Base filesystem archive not found: {self.info['fs']}")

        # Static analysis *must* have found some inits, otherwise we can't even start execution!
        inits_path = os.path.join(*[proj_dir, "static", "InitFinder.yaml"])
        if os.path.isfile(inits_path):
            with open(inits_path, "r") as f:
                self.inits = yaml.safe_load(f)

        if not self.inits:
            raise RuntimeError(
                f"No potential inits found during static analysis: {inits_path} is empty."
            )


def add_init_options_to_graph(config_manager, proj_dir, base_config):
    """
    A config needs to have an ['env']['igloo_init'] in order to do anything useful.
    We might have a single option already set or we might have multiple options
    stored proj_dir/static/InitFinder.yaml (based on static analysis).

    If we have no value set and no potential values, we raise an error.

    Otherwise we'll create a fake failure for "init" and a mitigation
    node to add each of the init options. Then we'll create configs
    with each init and add the necessary graph edges. This means
    we'll start our search with multiple configuration options (nodes)
    to explore.

    If an igloo_init is set in the initial config, we'll assume that's
    right and leave it alone.
    """
    # Hack igloo_inits into graph as a failure and mitigation.
    # But only if we don't have igloo_init set and have multiple
    # potential values
    if len(base_config.info["env"].get("igloo_init", [])) == 0:
        init_options = get_inits_from_proj(proj_dir)
        if len(init_options) == 0:
            raise RuntimeError(
                "No potential init binaries identified and none could be found"
            )

        base = config_manager.graph.get_node(base_config.gid)
        assert base is not None, f"BUG: base config {base_config} not in configuration"
        if base.run:
            raise RuntimeError(
                f"Base config {base_config} already ran, cannot add init options"
            )
        base.run = True

        # Add a fake failure
        init_fail = Failure("init", "init", {"inits": init_options})
        config_manager.graph.add_node(init_fail)
        # Connect back to baseline
        config_manager.graph.add_edge(base_config, init_fail)

        # Now for each, add mitigations and new config
        for init in init_options:
            # First add mitigation:
            this_init_mit = Mitigation(f"init_{init}", "init", {"init": init})
            config_manager.graph.add_node(this_init_mit)

            # Connect failure to mitigation
            config_manager.graph.add_edge(init_fail, this_init_mit, unknown=True)

            # Next add new config
            conf_info = deepcopy(base_config.info)
            conf_info["env"]["igloo_init"] = init
            new_config = Configuration(init, conf_info)
            config_manager.graph.add_node(new_config)

            # Connect new config to mitigation and parent config
            config_manager.graph.add_edge(base_config, new_config, delta=f"init={init}")
            config_manager.graph.add_edge(this_init_mit, new_config)


def report_best_results(best_idx, best_output, output_dir):
    with open(os.path.join(output_dir, "best.txt"), "w") as f:
        f.write(str(best_idx))

    # Now let's examine the best run's netbinds to report on network binds
    netbinds = os.path.join(best_output, "netbinds.csv")
    # parse csv - headers are procname,ipvn,domain,guest_ip,guest_port
    net_procnames = set()
    net_count = 0

    if netbinds is not None:
        with open(netbinds, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                net_procnames.add(row["procname"])
                net_count += 1
    else:
        net_count = 0

    with open(os.path.join(output_dir, "result"), "w") as f:
        if net_count == 0:
            f.write("false\n")  # No network binds
        else:
            f.write(
                f"{len(net_procnames)} unique processes bound to {net_count} network sockets\n"
            )

def graph_search(
    proj_dir, initial_config, output_dir, timeout, max_iters=1000,
    nthreads=1, init=None, verbose=False
):
    """
    Main entrypoint. Given an initial config and directory run our
    graph search.
    """

    run_index = AtomicCounter(0)
    active_worker_count = AtomicCounter(0)

    run_base = os.path.join(output_dir, "runs")
    os.makedirs(run_base, exist_ok=True)

    dump_config(initial_config, os.path.join(output_dir, "base_config.yaml"))

    base_config = Configuration("baseline", initial_config)
    config_manager = ConfigurationManager(base_config)
    global_state = GlobalState(proj_dir, output_dir, base_config.info)

    # We created a config node with our initial config as .info
    # Let's see if we can find it?
    # assert(config_manager.graph.get_existing_node(base_config.info) is not None)

    # Add various init binaries to graph
    add_init_options_to_graph(config_manager, proj_dir, base_config)

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
            worker_instance = Worker(
                global_state,
                config_manager,
                proj_dir,
                run_base,
                max_iters,
                run_index,
                timeout,
                active_worker_count,
                thread_id=idx,
                verbose=verbose
            )
            t = Thread(target=worker_instance.run)
            # t.daemon = True
            t.start()
            worker_threads.append(t)

        # Wait for all threads to finish
        for t in worker_threads:
            try:
                t.join()  # This isn't working well for multi-threaded shutdowns
            except KeyboardInterrupt:
                print(
                    "Keyboard interrupt while waiting for threads to finish - killing"
                )
                raise
    else:
        # Single thread mode, try avoiding deadlocks by just running directly
        Worker(
            global_state,
            config_manager,
            proj_dir,
            run_base,
            max_iters,
            run_index,
            active_worker_count,
        ).run()

    # We're all done! In the .finished file we'll write the final run_index
    # This way we can tell if a run is done early vs still in progress
    with open(os.path.join(output_dir, "finished.txt"), "w") as f:
        f.write(str(run_index.get()))

    # Let's also write a best.txt file with run index of the best run
    if best := config_manager.graph.get_best_run_configuration():
        report_best_results(
            best.run_idx,
            os.path.join(*[run_base, str(best.run_idx), "output"]),
            output_dir,
        )

def main():
    import sys

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <proj_dir> <config> <outdir>")
        sys.exit(1)

    config = load_config(sys.argv[1], sys.argv[2])
    graph_search(sys.argv[1], config, sys.argv[3])


if __name__ == "__main__":
    main()
