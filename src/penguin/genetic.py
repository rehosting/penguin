import os
import csv
from penguin import getColoredLogger
from threading import Lock, RLock

from .common import yaml
from .graphs import Configuration, ConfigurationManager
from .penguin_config import dump_config, hash_yaml_config, load_config
from .utils import AtomicCounter, get_mitigation_providers
from .manager import GlobalState

from penguin.analyses import PenguinAnalysis

from dataclasses import dataclass
from typing import Optional

"""
Genetic Algorithm Configuration Search

Overall idea:
- We have a population of configurations
- A configuration is a chromosome
- Each set of potential mitigations for a given failure is a gene
- The fitness function is the health score
- We'll support all the usual GA operations: crossover, mutation, selection
"""

def ga_search(
    proj_dir, base_config, output_dir, max_iters=1000, nthreads=1, init=None
):
    """
    Main entrypoint. Given an initial config and directory run our
    genetic algorithm search.
    """

    run_index = AtomicCounter(0)
    active_worker_count = AtomicCounter(0)

    run_base = os.path.join(output_dir, "runs")
    os.makedirs(run_base, exist_ok=True)

    dump_config(base_config, os.path.join(output_dir, "base_config.yaml"))

    global_state = GlobalState(proj_dir, output_dir, base_config)

    #Our first gene are the init options
    population = ConfigPopulation(base_config)
    init_gene = create_init_gene(global_state, base_config)
    population.extend_chromosome(list(population.chromosomes)[0], init_gene)

    worker_threads = []
    if nthreads > 1:
        for idx in range(nthreads):
            worker_instance = Worker(
                global_state,
                population,
                proj_dir,
                run_base,
                max_iters,
                run_index,
                active_worker_count,
                thread_id=idx,
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
            population,
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

def create_init_gene(global_state, base_config):
    """
    Based on add_init_options_to_graph in manager.py

    A config needs to have an ['env']['igloo_init'] in order to do anything useful.
    We might have a single option already set or we might have multiple options
    stored in our global_state (based on static analysis).

    If we have no value set and no potential values, we raise an error.

    Otherwise we'll create a fake failure for "init" and a mitigation
    node to add each of the init options. Then we'll create configs
    with each init. This means we'll start our search with multiple configuration
    options to explore.

    If an igloo_init is set in the initial config, we'll assume that's
    right and leave it alone.
    """
    # Hack igloo_inits as a gene
    # But only if we don't have igloo_init set and have multiple
    # potential values

    # Add a fake failure
    init_fail = Failure("init", "init", {"inits": global_state.inits})
    init_mitigations = set()

    if len(base_config["env"].get("igloo_init", [])) == 0:
        if len(global_state.inits) == 0:
            raise RuntimeError(
                "No potential init binaries identified and none could be found"
            )

        for init in global_state.inits:
            # First add mitigation:
            this_init_mit = Mitigation(f"init_{init}", "init", {"env": {"igloo_init": init}})
            init_mitigations.add(dict_to_frozenset(this_init_mit))
    else:
        #If we already have an init defined, we'll just use that
        init_mitigations.add(dict_to_frozenset({'env': { 'igloo_init': base_config["env"]["igloo_init"]}}))
    return MitigationGene(init_fail, frozenset(init_mitigations))

#TODO: should these move to common?
def dict_to_frozenset(d):
    # Recursively convert dictionaries and lists to frozensets and tuples
    if isinstance(d, dict):
        return frozenset((k, dict_to_frozenset(v)) for k, v in d.items())
    elif isinstance(d, list):
        return tuple(dict_to_frozenset(item) for item in d)
    else:
        return d

#TODO: should these move to common?
def frozenset_to_dict(fs):
    # Recursively convert frozensets and tuples back to dictionaries and lists
    if isinstance(fs, frozenset):
        return {k: frozenset_to_dict(v) for k, v in fs}
    elif isinstance(fs, tuple):
        return [frozenset_to_dict(item) for item in fs]
    else:
        return fs


@dataclass(frozen=True, eq=True)
class Failure:
    name: str
    type: str
    info: frozenset

    def __init__(self, name, type, info: dict):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "type", type)
        if info is None:
            object.__setattr__(self, "info", frozenset())
        else:
            object.__setattr__(self, "info", frozenset(dict_to_frozenset(info)))

@dataclass(frozen=True, eq=True)
class Mitigation:
    name: str
    type: str
    config_opts: frozenset

    def __init__(self, name, type, config_opts: dict):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "type", type)
        object.__setattr__(self, "config_opts", frozenset(dict_to_frozenset(config_opts)))

@dataclass(frozen=True, eq=True)
class MitigationGene:
    #might make more sense to have these live in a different data structure, not just in their chromosomes
    #grow them globally (list or something per failure)
    failure: Failure
    mitigations: frozenset #probably not frozen or do we do a new set?

class GenePool:
    #The Gene Pool is the set of all possible mitigations for a given failure
    #We would need to swap out a gene for each failure
    def __init__(self):
        self.lock = RLock()
        self.genes = dict()
        #TODO look into the data structure for indexing failures here

    def add(self, gene: MitigationGene):
        with self.lock:
            if gene.failure.name not in self.genes:
                self.genes[gene.failure.name] = set()
            self.genes[gene.failure.name].add(gene)

class ConfigChromosome:
    #At the end of the day, each "chromosome" is going to be a configuration. Which is set of mitigations
	#We are using a frozenset since each chromosome will be unique
    #Should we have a base configuration or a set of mitigations?
    genes: frozenset[MitigationGene]
    def __init__(self, base_config: dict, old_chromosome: 'ConfigChromosome' = None, new_gene: MitigationGene = None):
        self.lock = RLock()
        if old_chromosome is None:
            base_failure = Failure("base", "base", None) #create a "failure" for the base config
            base_mitigation = MitigationGene(base_failure, mitigations=dict_to_frozenset(base_config))
            self.genes = frozenset({base_mitigation})
            old_chrmosome = self
        if new_gene is not None:
            self.genes = frozenset(old_chromosome.genes.union([new_gene]))

class ConfigPopulation:
    def __init__(self, base_config):
        self.lock = RLock()
        self.base_config = base_config #store the base configuration, assumes it is immutable
        self.chromosomes = set({ConfigChromosome(base_config, None, None)})
        self.nelites = 1 #number of elites to keep 
        self.attempted_configs = set() #store the configurations we've already tried - do we need this with the cache?
        self.pool = GenePool() #store the pool of all possible mitigations


	#This is where the biology breaks down a bit. We'll add a new chromosome to the population based on an observed failure
    def extend_chromosome(self, parent: ConfigChromosome, new_mitigation: MitigationGene):
        self.pool.add(new_mitigation)
        with self.lock:
            self.chromosomes.add(ConfigChromosome(self.base_config, parent, new_mitigation))

        #for selection, do we want to still bias towards newly discovered failures?

class Worker:
    def __init__(
        self,
        global_state,
        population,
        proj_dir,
        run_base,
        max_iters,
        run_index,
        active_worker_count,
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
        self.logger = logger or getColoredLogger(
            f"mgr_ga{self.thread_id if self.thread_id is not None else ''}.run.{self.run_index.get()}"
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

def main():
    import sys

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <config> <outdir>")
        sys.exit(1)

    config = load_config(sys.argv[1])
    ga_search(os.path.dirname(sys.argv[1]), config, sys.argv[2])


if __name__ == "__main__":
    main()
