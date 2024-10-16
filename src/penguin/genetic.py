import os
import csv
import sys
import random
import logging
import re
from types import SimpleNamespace
from penguin import getColoredLogger
from threading import Lock, RLock
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from copy import deepcopy

from .common import yaml
from .graphs import Configuration, ConfigurationManager
from .penguin_config import dump_config, hash_yaml_config, load_config
from .utils import AtomicCounter, get_mitigation_providers
from .manager import GlobalState, PandaRunner, calculate_score, Worker
from .graphs import Failure

from penguin.analyses import PenguinAnalysis

from dataclasses import dataclass
from typing import Optional, Callable, Tuple, List, Set

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
    proj_dir, base_config, output_dir, max_iters=1000, nthreads=1, init=None, pop_size=8
):
    """
    Main entrypoint. Given an initial config and directory run our
    genetic algorithm search.
    """

    logger = getColoredLogger("penguin.ga_explore")
    logger.setLevel(logging.DEBUG)


    run_base = os.path.join(output_dir, "runs")
    os.makedirs(run_base, exist_ok=True)
    dump_config(base_config, os.path.join(output_dir, "base_config.yaml"))

    #pass a copy of the base config to the global state so it doesn't slice out things we want to keep
    global_state = GlobalState(proj_dir, output_dir, deepcopy(base_config))

    #Our first gene are the init options, do this outside of the population class
    population = ConfigPopulation(global_state, base_config, run_base, logger, pop_size)
    init_gene = create_init_gene(base_config, global_state)
    population.extend_genome(None, init_gene)
    old_learning_configs = set() #store the learning configs we've already tried

    for iter in range(1,max_iters+1,1):
        logger.info(f"Starting generation {iter}/{max_iters} with {len(population.chromosomes)} configurations, {len(population.pool.genes)} genes, and {nthreads} workers")

        #we'll store a dict of {chromosome: {failures: [], scores: dict, fitness: float}}
        results = population.run_configs(nthreads, population.chromosomes)

        #at this point, results contains the fitness and failures for each chromosome
        #now, go through and record the fitnesses, and update mitigations based on failures
        mitigations = set()
        for config in population.chromosomes:
            try:
                result = results[config.hash]
                population.record_fitness(config, result["fitness"])
            except Exception as e:
                logger.error(f"Error recording fitness for {config}: {e}")
                import IPython; IPython.embed()
                #raise e
            full_config = population.get_full_config(config)
            dummy_config = SimpleNamespace(info=full_config,exclusive=None)
            providers = get_mitigation_providers(full_config)
            learning_configs=set() #mitigations we'll use to learn more (exclusive in the graph paralence)
            for f in result["failures"]:
                for pm in providers[f.type].get_potential_mitigations(full_config, f):
                    #pm in this case in a Mitigation(GraphNode)
                    for m in providers[f.type].implement_mitigation(dummy_config, f, pm):
                        #m in this case in a Configuration(GraphNode), which is a full configuration
                        diff = diff_configs(m.info, full_config)
                        new_mit = Mitigation(f, f.type, dict_to_frozenset(diff))
                        if m.exclusive:
                            #we'll add a new config based on this config with the exclusive mitigation
                            learning_config = ConfigChromosome(config, new_mit)
                            if learning_config.hash not in old_learning_configs:
                                old_learning_configs.add(learning_config.hash)
                                learning_configs.add(learning_config)
                        else:
                            mitigations.add(new_mit)

            #at this point we run all the learning configs, and process results again - FIXME refactor
            learning_results=population.run_configs(nthreads, learning_configs)

            #and we need to now process those mitigations, almost the same as above but we won't track
            #score since these were theoretically no different than before - just with learning stuff
            #(might want to account into some aggregate score later)
            for l in learning_configs:
                full_config = population.get_full_config(l)
                dummy_config = SimpleNamespace(info=full_config,exclusive=None)
                providers = get_mitigation_providers(full_config)
                result = learning_results[l.hash]
                for f in result["failures"]:
                    #TypeError: unhashable type: 'set' from below line:
                    for pm in providers[f.type].get_potential_mitigations(full_config, f):
                        #pm in this case in a Mitigation(GraphNode)
                        for m in providers[f.type].implement_mitigation(dummy_config, f, pm):
                            #m in this case in a Configuration(GraphNode), which is a full configuration
                            diff = diff_configs(m.info, full_config)
                            new_mit = Mitigation(f, f.type, dict_to_frozenset(diff))
                            if m.exclusive:
                                #we'll add a new config based on this config with the exclusive mitigation
                                #raise("Exclusive mitigations not supported in learning step")
                                logger.warn("Exclusive mitigations not supported in learning step")
                            else:
                                mitigations.add(new_mit)

            #TODO: did we want to run any new mitigations to get some fitness data on them before we used them?

            #at this point, we've processed all configs and ran a learning step. we now have
            #  * a set of mitigations from our population
            #  * fitnesses for each configuration in our population

            #First, we update the gene pool with mitigations we've learned
            for m in mitigations:
                population.pool.update(m)

            #select half of the exsiting configs to move on as parents of the next generation
            #if the population is less than the number of parents expect, we'll add them all and duplicate
            population.selection(pop_size/2)

            #we now have parents, do crossover, we'll do a 50-50 mix
            population.crossover(0.5)

            #and mutation, for now we'll do one gene
            population.mutation(1)


    # Below is to give results comparable to the graph search
    # We're all done! In the .finished file we'll write the final run_index
    # This way we can tell if a run is done early vs still in progress
    with open(os.path.join(output_dir, "finished.txt"), "w") as f:
        f.write(str(population.run_index.get()))

    # Let's also write a best.txt file with run index of the best run
    # TODO: implement this

    #Look through all the run dirs and find the latest fitness.txt (float)
    #Then, find the highest one
    #Write that to best.txt
    #If we have a tie, we'll just pick the first one
    best_fitness = 0.0
    best_run = 0
    for run in os.listdir(run_base):
        fitness_file = os.path.join(run_base, run, "fitness.txt")
        if os.path.isfile(fitness_file):
            with open(fitness_file, "r") as f:
                fitness = float(f.readline())
                if fitness > best_fitness:
                    best_fitness = fitness
                    best_run = run
    with open(os.path.join(output_dir, "best.txt"), "w") as f:
        f.write(str(best_run))
    logger.info(f"Best run: {best_run} with fitness {best_fitness}")



def create_init_gene(base_config, global_state):
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
    init_mitigations = set()

    if len(base_config["env"].get("igloo_init", [])) == 0:
        if len(global_state.inits) == 0:
            raise RuntimeError(
                "No potential init binaries identified and none could be found"
            )

        for init in global_state.inits:
            # First add mitigation:
            this_init_mit = Mitigation(f"init_{init}", "init", {"env": {"igloo_init": init}})
            init_mitigations.add(this_init_mit)
    else:
        #If we already have an init defined, we'll just use that
        mit =  Mitigation(f"init", "init", {'env': { 'igloo_init': base_config["env"]["igloo_init"]}})
        init_mitigations.add(mit)
    return MitigationAlleleSet("init", frozenset(init_mitigations))

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

#This is absolutely horrible, but thing we need it for the bolt on approach to testing out this new search
#Note: this does not support keys that were *removed)
def diff_configs(new, old):
    diff = {}

    for k in new:
        if k not in old:
            diff[k] = new[k]
        elif isinstance(new[k], dict) and isinstance(old[k], dict):
            nested_diff = diff_configs(new[k], old[k])
            if nested_diff:  # Only include if there's a difference
                diff[k] = nested_diff
        elif new[k] != old[k]:
            diff[k] = new[k]

    return diff

@dataclass(frozen=True, eq=True)
class Mitigation:
    """
    This class represents a specific mitigation for a given failure
    A configuration is a set of these
    """
    name: str
    type: str
    config_opts: frozenset

    def __init__(self, name, type, config_opts: dict):
        if isinstance(name, Failure):
            object.__setattr__(self, "name", GenePool.failure_to_genename(name))
        elif isinstance(name, str):
            object.__setattr__(self, "name", name)
        else:
            raise(RuntimeError(f"Unexpected type for Mitigation name {name}: {type(name)}"))
        object.__setattr__(self, "type", type)
        object.__setattr__(self, "config_opts", frozenset(dict_to_frozenset(config_opts)))

@dataclass(frozen=True, eq=True)
class MitigationAlleleSet:
    """
    This class contains the set of mitigations we know about for a given failure
    In the biology analogy, each mitigation would be an allele
    """
    failure_name: str
    mitigations: frozenset #probably not frozen or do we do a new set?

class GenePool:
    """
    The gene pool tracks the set of possible mitigations for a given failure
    """
    def __init__(self):
        self.genes = dict()
        #TODO look into the data structure for indexing failures here

    def update(self, new_gene):
        if isinstance(new_gene, MitigationAlleleSet):
            failure_name = new_gene.failure_name
            new_mits = new_gene.mitigations
        elif isinstance(new_gene, Mitigation):
            failure_name = new_gene.name
            new_mits = frozenset([new_gene])
        else:
            raise(RuntimeError(f"Unexpected datatype for new_gene {new_gene}: {type(new_gene)}"))

        if failure_name not in self.genes:
            self.genes[failure_name] = new_mits
        else:
            current_mitigations = self.genes[failure_name]
            self.genes[failure_name] = frozenset(current_mitigations.union(new_mits))

    def get_mitigations(self, failure):
        if isinstance(failure, Failure):
            failure_name = failure_to_genename(failure)
        elif isinstance(failure, str):
            failure_name = failure
        else:
            print(RuntimeError(f"Unexpected datatype for failure {failure}: {type(failure)}"))
            import IPython; IPython.embed()
        return self.genes.get(failure_name, frozenset())

    def failure_to_genename(failure: Failure):
        #HACK: interfaces return overly unique names so they wouldn't be considered the same gene
        if failure.type == "interfaces":
            name = re.sub(r'_\d+$', '', failure.friendly_name)
            return f"{failure.type}_{name}"
        else:
            return f"{failure.type}_{failure.friendly_name}"

    def get_names(self):
        return self.genes.keys()

class ConfigChromosome:
    #At the end of the day, each "chromosome" is going to be a configuration. Which is set of mitigations
    #We are using a frozenset since each chromosome will be unique
    #We do not keep the immutable base config in here since that is held in GlobalState
    genes: frozenset[Mitigation]
    hash: int
    def __init__(self, parent: 'ConfigChromosome' = None, new_gene = None):
        self.genes = frozenset()
        if parent is None:
            parent = self #weird
        elif not new_gene.name.startswith("init"):
            try:
                assert len(parent.genes) > 0, "If there's a parent and we aren't adding init, it must have genes"
            except AssertionError as e:
                print("Debugging ConfigChromosome constructor")
                print("Parent genes: ", parent.genes)
                print("new_gene: ", new_gene)
                import IPython; IPython.embed()
        if isinstance(new_gene, Mitigation):
            old_genes = parent.genes #faded and with lots of holes
            if old_gene := parent.get_mitigation(new_gene.name):
                #If we had this gene, replace it with the new one. This is for mutations
                old_genes = old_genes.difference({old_gene})
            self.genes = frozenset(old_genes.union({new_gene}))
        elif isinstance(new_gene, frozenset):
            self.genes = new_gene
        #cache the unsigned hash of genes, not sure how much this actually buys us
        self.hash = hash(self.genes) & (1 << sys.hash_info.width) - 1

    def __str__(self):
        return f"{self.hash:016x}"

    def to_dict(self):
        config_dict = {}
        #TODO: should we do some validation to make sure our config doesn't have conflicting options?
        for m in self.genes:
            sub_dict = frozenset_to_dict(m.config_opts)
            for k, v in sub_dict.items():
                if k in config_dict:
                    if isinstance(config_dict[k], list):
                        config_dict[k].extend(v)
                    elif isinstance(config_dict[k], dict):
                        config_dict[k].update(v)
                    else:
                        raise(RuntimeError(f"Unexpected type for config key {k}: {type(config_dict[k])}"))
                else:
                    config_dict[k] = v
        return config_dict

    def get_mitigation(self, failure_name):
        assert(isinstance(failure_name, str)), "Failure name must be a string"
        for m in self.genes:
            if m.name == failure_name:
                return m
        return None

    def mitigations_to_str(self):
        return "\n".join(f"{m.name}: {m.config_opts}" for m in self.genes)

class ConfigPopulation:
    def __init__(self, global_state, base_config, run_base, logger, pop_size, nelites=1):
        self.global_state = global_state
        self.base_config = deepcopy(base_config) #store the base configuration, assumes it is immutable
        self.chromosomes = set()
        self.attempted_configs = set() #store the configurations we've already tried - do we need this with the cache?
        self.pool = GenePool() #store the pool of all possible mitigations
        self.work_queue = Queue() #store the work queue of configurations to run
        self.run_index = AtomicCounter(-1) #store the run index, start at -1 since we increment before using
        self.logger = logger
        self.run_base = run_base
        self.lock = RLock() #lock for shared state
        self.fitnesses = dict() #cache the fitness of each configuration
        self.pop_size = pop_size
        self.parents = []
        self.nelites = nelites #number of elites to keep in the next generation

    #This is where the biology breaks down a bit. We'll add a new chromosome to the population based on an observed failure
    def extend_genome(self, parent: ConfigChromosome, new_gene: MitigationAlleleSet):
        #First, check to see if we have existing mitigations for this failure
        old_mitigations = self.pool.get_mitigations(new_gene.failure_name)
        self.pool.update(new_gene) #our pool contains all possible mitigations for a given failure
        #If we have new mitigations, add them as children to this config
        #In the biology analogy, these things would be alleles
        for m in new_gene.mitigations.difference(old_mitigations):
            self.chromosomes.add(ConfigChromosome(parent, m))

    def run_configs(self, nthreads: int, chromosomes: Set[ConfigChromosome]):
        results = {}
        with ThreadPoolExecutor(max_workers=nthreads) as executor:
            for tid in range(nthreads):
                try:
                    executor.submit(self.run_worker, id=tid, results=results)
                except Exception as e:
                    self.logger.error(f"Error in run_worker: {e}")
                    raise e

            self.create_work_queue(nthreads, chromosomes)
            self.join_workers(nthreads)
        return results

    def run_worker(self,
        id: int,
        results: dict
    ):
        while True:
            #A unit of work is a configuration to run along with the run index
            self.logger.info(f"[thread {id}]: Getting work from queue")

            task = self.work_queue.get()

            if task is None:
                self.logger.info(f"[thread {id}]: Got task None from queue, exiting")
                self.work_queue.task_done()
                break

            try:
                config, run_index = task
                self.logger.info(f"[thread {id}]: Running config {config} with run index {run_index}")
                failures, scores = self.run_config(config, run_index)
                with self.lock:
                    results[config.hash] = {"failures": failures, "scores": scores,
                                            "fitness":  float(sum(scores.values()))}
            except Exception as e:
                self.logger.error(f"[thread {id}]: Error running config {config} with run index {run_index}: {e}")
                self.work_queue.task_done()

            self.work_queue.task_done()
            self.logger.info(f"[thread {id}]: Finished config {config} with run index {run_index}")

    def create_work_queue(self, nworkers: int, chromosomes: Set[ConfigChromosome]):
        for chromosome in chromosomes:
            self.work_queue.put((chromosome, self.run_index.increment()))
        for _ in range(nworkers):
            self.work_queue.put(None)

    def join_workers(self,nworkers=1):
        self.logger.info(f"Joining workers...")
        self.work_queue.join()
        self.logger.info(f"Joined workers")

    def get_full_config(self, config: ConfigChromosome):
        """
        Given a configuration, return the full configuration (base_config+config)
        """
        combined_config = deepcopy(self.base_config)
        combined_config.update(config.to_dict())
        return combined_config

    def run_config(self, config: ConfigChromosome, run_index: int) -> Tuple[List[Failure], float]:
        """
        Careful! This function is run in parallel and should not modify any shared state.

        This is very dirty - we return the failure type from graph.py, not our own Failure class

        We also tack on the base config, so watch out for that.
        """
        failures = [] #TODO: should we track only new failures?
        score = {"empty": 0.0}

        if self.get_fitness(config) != False:
            self.logger.info(f"Skipping config {config} since it has already been tried")
            return failures, {"previous_run": self.get_fitness(config)}

        run_dir = os.path.join(self.run_base, str(run_index))
        if os.path.isdir(run_dir):
            # Remove it
            shutil.rmtree(run_dir)
        os.makedirs(run_dir)
        self.logger.info(f"Running config {config} in {run_dir}")

        # Write config to disk
        full_config = self.get_full_config(config)
        dump_config(full_config, os.path.join(run_dir, "config.yaml"))

        # Run the configuration
        conf_yaml = os.path.join(run_dir, "config.yaml")

        timeout = full_config.get("plugins", {}).get("core", {}).get("timeout", None)
        out_dir = os.path.join(run_dir, "output")
        os.makedirs(out_dir, exist_ok=True)
        #Stash genes in the run directory
        with open(os.path.join(run_dir, "genes.txt"), "w") as f:
            output=f"Config: {config.hash}\n"
            f.write(output+config.mitigations_to_str())
        try:
            PandaRunner().run(conf_yaml, self.global_state.proj_dir, out_dir, timeout=timeout)

        except RuntimeError as e:
            # Uh oh, we got an error while running. Warn and continue
            self.logger.error(f"Could not run {run_dir}: {e}")
            return [], 0, None

        #Now, get the score and failures
        score = calculate_score(out_dir)
        with open(os.path.join(run_dir, "fitness.txt"), "w") as f:
            total = float(sum(score.values()))
            f.write(f"{total}\n")

        #HACK: fake out config into the format that graph stuff expects by creating "Worker"
        worker = Worker(
            self.global_state, #global_state
            None, #config_manager
            self.global_state.proj_dir, #proj_dir,
            run_dir, #run_base,
            1, #max_iters,
            run_index,
            1, #active_worker_count,
            thread_id=id,
            logger=self.logger,
            )
        fake_graph_node = SimpleNamespace(info=full_config,exclusive=None)
        failures = worker.analyze_failures(run_dir, fake_graph_node, 1)
        #end HACK

        return failures, score

    def record_fitness(self, config: ConfigChromosome, fitness):
        if config.hash not in self.fitnesses:
            self.fitnesses[config.hash] = fitness
        else:
            #If we decide to really hold on to an elite, could wind up here
            #But with the large number of possibilities we shouldn't end up here
            self.logger.info(f"Double record! Fitness for {config.hash} already recorded")

    def get_fitness(self, config: ConfigChromosome):
        return self.fitnesses.get(config.hash, False)

    def config_in_pop(self, config: ConfigChromosome):
        return config.hash in [c.hash for c in self.chromosomes]

    def selection(self, nparents):
        """
        A ranked based selection. We'll choose nparents to move on to the next generation

        By default, hold on to the highest fitness config (nelites=1)
        """
        self.parents = []
        #get current population, sorted by fitness, higher is better (e.g., 6/6 is better than 5/6)
        if len(self.chromosomes) == 0:
            sorted_configs = []
        else:
            sorted_configs = sorted(self.chromosomes, key=lambda c: self.get_fitness(c))

        #probability of a selecting each config, weighted rank based selection
        n = len(sorted_configs)
        norm = n*(n+1)/2
        probs = [(i+1)/norm for i in range(0,n)]

        #select nparents based on the probabilities
        #first, if we have duplicates, we'll just add them
        if n < nparents:
            self.parents = sorted_configs

        if self.nelites > 0:
            elites = sorted_configs[-self.nelites:n]
            self.parents.extend(elites)

        while len(self.parents) < nparents:
            r = random.random()
            for i in range(n):
                if r < probs[i]:
                    # only allow duplicates if our starting population is too small
                    # they very well may get reduced in the crossover step, but we want this functionality
                    # should our approach to crossover change
                    if sorted_configs[i] not in self.parents or n < nparents:
                        self.parents.append(sorted_configs[i])
                    break
        self.logger.info(f"Selected {len(self.parents)} parents from {n} configs")
        self.logger.debug(f"parents:\n {self.print_chromosomes(self.parents)}")


    def crossover(self, p1_prob=0.5):
        """
        Perform crossover on the parents to create new children, choose from p1 with probability p1_prob
        """

        #Pass elites through unscathed
        self.chromosomes = set(self.parents[:self.nelites])
        self.parents = self.parents[self.nelites:]

        #cross over neighbors in the parent list
        for i in range(0,len(self.parents),2):
            try:
                p1 = self.parents[i]
                p2 = self.parents[i+1]
            except IndexError:
                #lazily handle odd number of parents
                break
            child = ConfigChromosome()
            for gene in self.pool.get_names():
                #get the set of known mitigations for this gene
                #cross over the two parents, grabbing a mitigation from each
                if random.random() < p1_prob:
                    m1 = p1.get_mitigation(gene)
                    if m1:
                        child = ConfigChromosome(child, m1)
                    else:
                        m2 = p2.get_mitigation(gene)
                        if m2:
                            child = ConfigChromosome(child, m2)
                else:
                    m2 = p2.get_mitigation(gene)
                    if m2:
                        child = ConfigChromosome(child, m2)
                    else:
                        m1 = p1.get_mitigation(gene)
                        if m1:
                            child = ConfigChromosome(child, m1)

            #Only add this child if it is unique and has not been tried before
            #Since the population is a set, we don't have to check for duplicates
            if not self.get_fitness(child) and len(child.genes) > 0:
                try:
                    assert(child.get_mitigation("init_init")), "Missing init gene"
                    if not self.config_in_pop(child):
                        #Unfortunately, using sets didn't get us this diversity automagically
                        self.chromosomes.add(child)
                except AssertionError as e:
                    self.logger.error(f"Error in crossover: {e}")

        self.logger.info(f"Population size after crossover is: {len(self.chromosomes)}")
        self.logger.debug(f"population:\n{self.print_chromosomes(self.chromosomes)}")

    def mutation(self, nmuts=1):
        """
        Perform mutation on the population, we are going to be a bit more aggressive with mutation than traditional GAs

        Our mutation here is essentially "try a different mitigation". Elites will get modified here
        """
        #At this point, we have parents and a starter population with children from crossover, make new configs until are population is full
        while len(self.chromosomes) < self.pop_size:
            #Originally did a growing configchromosome, but that was buggy and inefficient
            genes = random.choice(self.parents).genes
            gene_names = [g.name for g in genes]

            #First, make sure we have all genes in this chromosome (with a possibility of no mitigation)
            #this allows us to get a bunch of diversity from learning configs
            print(f"Gene names: {gene_names}")
            print(f"Pool names: {self.pool.get_names()}")
            for g in self.pool.get_names():
                if g not in gene_names:
                    self.logger.debug(f"Adding missing gene {g}")
                    choices = self.pool.get_mitigations(g)
                    if not g.startswith("init"):
                        #init is special, don't allow that to be None. otherwise maybe "no mitigation" is what we'd like?
                        choices = choices.union({None})
                    m = random.choice(list(choices))
                    if m:
                        genes = genes.union({m})

            self.logger.debug(f"Mutating genes {genes}")
            for i in range(nmuts):
                gene = random.choice(list(self.pool.get_names()))
                self.logger.debug(f"Mutating gene {gene}")
                choices = self.pool.get_mitigations(gene)
                assert choices, f"No choices for gene {gene}"
                m = random.choice(list(choices))
                self.logger.debug(f"Mutation: {m}")
                self.logger.debug(f"Before mutation: {genes}")
                if m.name in [g.name for g in genes]:
                    #if we already have this gene, remove it
                    self.logger.debug(f"removing gene with name  {m.name}")
                    genes = genes.difference({g for g in genes if g.name == m.name})
                    self.logger.debug(f"all gene names (after removal): {[g.name for g in genes]}")
                child = ConfigChromosome(None, genes.union({m}))
                self.logger.debug(f"After mutation: {child.genes}")

            if child and not self.get_fitness(child) and not self.config_in_pop(child):
                #If we have exhausted our configuration space, this will cause an infinite loop...
                self.chromosomes.add(child)

        self.logger.info(f"Population size after mutation is: {len(self.chromosomes)}")
        self.logger.debug(f"population:\n{self.print_chromosomes(self.chromosomes)}")

    def print_chromosomes(self, chromosomes):
        return "\n".join([f"Chromosome {c}:\n{c.mitigations_to_str()}\n" for c in chromosomes])


def main():
    import argparse

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <config> <outdir>")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "config",
        type=str,
        help="Path to the configuration file",
    )
    parser.add_argument(
        "outdir",
        type=str,
        help="Path to the output directory",
    )
    parser.add_argument(
        "--niters",
        type=int,
        default=100,
        help="Number of iterations to run. Default is 100.",
    )
    parser.add_argument(
        "--nworkers",
        type=int,
        default=4,
        help="Number of workers to run in parallel. Default is 4",
    )
    args = parser.parse_args()
    config = load_config(args.config)
    ga_search(os.path.dirname(args.config), config, args.outdir, args.niters, args.nworkers)


if __name__ == "__main__":
    main()
