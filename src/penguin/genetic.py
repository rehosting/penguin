import os
import csv
from penguin import getColoredLogger
from threading import Lock, RLock
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

from .common import yaml
from .graphs import Configuration, ConfigurationManager
from .penguin_config import dump_config, hash_yaml_config, load_config
from .utils import AtomicCounter, get_mitigation_providers
from .manager import GlobalState

from penguin.analyses import PenguinAnalysis

from dataclasses import dataclass
from typing import Optional, Callable

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

    logger = getColoredLogger("penguin.ga_explore")

    run_base = os.path.join(output_dir, "runs")
    os.makedirs(run_base, exist_ok=True)

    dump_config(base_config, os.path.join(output_dir, "base_config.yaml"))

    global_state = GlobalState(proj_dir, output_dir, base_config)

    #Our first gene are the init options
    population = ConfigPopulation(base_config)
    init_gene = create_init_gene(global_state, base_config)
    population.extend_chromosome(list(population.chromosomes)[0], init_gene)

    for iter in range(max_iters):
        logger.info(f"Starting iteration {iter}")

        # Use a dynamic thread pool to run all configurations
        with ThreadPoolExecutor(max_workers=nthreads) as executor:
            for tid in range(nthreads):
                try:
                    executor.submit(population.run_generation,
                            logger=logger,
                            id=tid,
                    )
                except Exception as e:
                    logger.error(f"Error in run_generation: {e}")
                    raise e

            population.create_work_queue()
            population.join_workers(ntreads)

        #TODO: implement selection, crossover, mutation now that we've run the generation

    """
    # We're all done! In the .finished file we'll write the final run_index
    # This way we can tell if a run is done early vs still in progress
    with open(os.path.join(output_dir, "finished.txt"), "w") as f:
        f.write(str(run_index.get()))

    # Let's also write a best.txt file with run index of the best run
    # TODO: implement this
    if best := config_manager.graph.get_best_run_configuration():
        report_best_results(
            best.run_idx,
            os.path.join(*[run_base, str(best.run_idx), "output"]),
            output_dir,
        )
    """

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
        self.genes = dict()
        #TODO look into the data structure for indexing failures here

    def add(self, gene: MitigationGene):
        if gene.failure.name not in self.genes:
            self.genes[gene.failure.name] = set()
        self.genes[gene.failure.name].add(gene)

class ConfigChromosome:
    #At the end of the day, each "chromosome" is going to be a configuration. Which is set of mitigations
	#We are using a frozenset since each chromosome will be unique
    #Should we have a base configuration or a set of mitigations?
    genes: frozenset[MitigationGene]
    def __init__(self, base_config: dict, old_chromosome: 'ConfigChromosome' = None, new_gene: MitigationGene = None):
        if old_chromosome is None:
            base_failure = Failure("base", "base", None) #create a "failure" for the base config
            base_mitigation = MitigationGene(base_failure, mitigations=dict_to_frozenset(base_config))
            self.genes = frozenset({base_mitigation})
            old_chrmosome = self
        if new_gene is not None:
            self.genes = frozenset(old_chromosome.genes.union([new_gene]))

class ConfigPopulation:
    def __init__(self, base_config):
        self.base_config = base_config #store the base configuration, assumes it is immutable
        self.chromosomes = set({ConfigChromosome(base_config, None, None)})
        self.nelites = 1 #number of elites to keep 
        self.attempted_configs = set() #store the configurations we've already tried - do we need this with the cache?
        self.pool = GenePool() #store the pool of all possible mitigations
        self.work_queue = Queue() #store the work queue of configurations to run


	#This is where the biology breaks down a bit. We'll add a new chromosome to the population based on an observed failure
    def extend_chromosome(self, parent: ConfigChromosome, new_mitigation: MitigationGene):
        self.pool.add(new_mitigation)
        self.chromosomes.add(ConfigChromosome(self.base_config, parent, new_mitigation))

    def run_generation(self,
        logger: Optional[Callable[[str], None]] = None,
        id: Optional[int] = 0,
    ):
        while True:
            config = self.work_queue.get()

            if config is None:
                #FIXME: not getting sentinel here
                self.work_queue.task_done()
                break

            if logger is not None:
                logger.info(f"[thread {id}]: Running config {config}")
            #failures, health_score, run_idx = run_config_f(config)

            self.work_queue.task_done()
            logger.info(f"[thread {id}]: Finished config {config}")

    def create_work_queue(self):
        for chromosome in self.chromosomes:
            self.work_queue.put(chromosome)

    def join_workers(self,nworkers=1):
        logger.info(f"Joining workers...")
        self.work_queue.join()
        logger.info(f"Joined workers")
        for _ in range(nworkers):
            self.work_queue.put(None)

def main():
    import sys

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <config> <outdir>")
        sys.exit(1)

    config = load_config(sys.argv[1])
    ga_search(os.path.dirname(sys.argv[1]), config, sys.argv[2])


if __name__ == "__main__":
    main()
