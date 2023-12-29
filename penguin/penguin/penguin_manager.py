import os
import time
import math
import shutil
import pandas as pd
import networkx as nx
import subprocess
import logging

from typing import List, Tuple
from copy import deepcopy
from random import choice
from threading import Thread, Lock
import coloredlogs

from .common import yaml
from .penguin_prep import prepare_run
from .utils import load_config, dump_config, hash_yaml_config, AtomicCounter, _load_penguin_analysis_from

coloredlogs.install(level='INFO', fmt='%(asctime)s %(name)s %(levelname)s %(message)s')

SCORE_CATEGORIES = ['execs', 'bound_sockets', 'devices_accessed', 'processes_run', 'modules_loaded',
                    'blocks_covered', 'nopanic']

logger = logging.getLogger('mgr')

def get_mitigation_providers(config : dict ):
    """
    Given a config, pull out all the enabled mitigation providers,
    load them and return a dict of {ANALYSIS_TYPE: analysis class object}

    Skip plugins that are disabled in config.
    Raise an error if version of a plugin mismatches the config version
    """
    mitigation_providers = {} # ANALYSIS_TYPE -> analysis class object
    for plugin_name, details in config['plugins'].items():
        if 'enabled' in details and not details['enabled']:
            # Disabled plugin - skip
            continue
        try:
            analysis = _load_penguin_analysis_from(plugin_name + ".py")
        except ValueError as e:
            continue
        mitigation_providers[analysis.ANALYSIS_TYPE] = analysis
        if details['version'] != analysis.VERSION:
            raise ValueError(f"Config specifies plugin {plugin_name} at version {details['version']} but we got {analysis.VERSION}")

        #print(f"Loaded {plugin_name} at version {details['version']}")
    return mitigation_providers


class Node:
    def __init__(self, config_dict, parent=None, is_group=False, delta=None, weight=0):
        self.config = config_dict
        self.parent = parent
        self.is_group = is_group
        self.parent_delta = delta # What was changed from parent, if anything
        self.weight = weight # Huristic measuring significance of change over parent node. [0,1]. Higher is better

        self.failures = {} # failure_type -> {failure: [details]}

        self.children = []
        self.child_hashes = set() # Hashes of child configs to avoid dups
        self.run_count = 0 # How many times have we simulated/emulated this node?
        self.run_idx = 0 # What was the run index of this node when we ran it?

        #self.value = 0  # Sum of the values for the UCT calculation
        #self.score = 0 # Zero by default until it's run?
        self.visits = 0
        self.objectives = {k: 0.0 for k in SCORE_CATEGORIES} # Non-normalized, back-propagated
        self.normalized_objectives = {k: 0.0 for k in SCORE_CATEGORIES} # Normalized, back-propagated
        self.total_objectives = 0 # Just for debug printing: sum of all objectives. Not back-propagated

        self.lock = Lock()
        # For stringifying tree of Nodes
        self.depth = 0 if parent is None else parent.depth + 1
        self.width = 0 if parent is None else len(parent.children)

    def label(self):
        return f"{self.depth}x{self.width}"

    def add_config_failure(self, fail_type, fail_cause, fail_info=None):
        with self.lock:
            if fail_type not in self.failures:
                self.failures[fail_type] = {}

            if fail_cause in self.failures[fail_type] and self.failures[fail_type][fail_cause] != fail_info:
                logger.warn(f"Replacing failures[{fail_type}][{fail_cause}]'s {self.failures[fail_type][fail_cause]} with {fail_info}")
                #print(f"Ignoring request to add {fail_cause}={fail_info} to failures[{fail_type}][{fail_cause}] which arleady is {self.failures[fail_type][fail_cause]}")
                #return

            # We can't have a failure that's also a mitigation - if so we have a bug
            # XXX: Now we can - if we do a multi-stage mitigation (DYNAVAL/Symex) we'll have a failure that's "mitigated" by a more in-depth analysis
            # after which we'll have better mitigations
            #if fail_cause in self.config[fail_type]:
            #    raise ValueError(f"BUG: {fail_cause} is a failure and a mitigation")

            # We want to store some context along with failure. Or perhaps None
            # Note we don't expect to have objects that need merging, each fail should have one object returned
            self.failures[fail_type][fail_cause] = fail_info

    def add_child_if_new(self, child):
        h = hash_yaml_config(child.config)
        if self.parent:
            with self.parent.lock:
                if h in self.parent.child_hashes:
                    # Our child is either ourself or one of our siblings
                    # Did we not transform it at all?
                    return False

        with self.lock:
            if h not in self.child_hashes:
                assert(child.failures == {}), f"How did child inherit failures: {child.failures}" # Pretty sure this is impossible
                self.children.append(child)
                self.child_hashes.add(h)
                return True
        return False

    def stringify_config(self):
        out = ""
        for k, v in self.config.items():
            if k in ["plugins"] or not len(v):
                continue
            out += f"\n\t{k}"
            for fail_name, fail_info in v.items():
                out += f"\n\t\t{fail_name}: {fail_info}"
        return out

    def stringify_failures(self):
        out = ""
        for k, v in self.failures.items():
            if not len(v):
                continue
            out += f"\n\t{k}"
            for key, value in v.items():  # Assuming v is a dictionary
                out += f"\n\t\t{key}: {value}"
        if not len(out):
            out = "(none)"
        return out

    def __repr__(self):
        out = f"Node{self.label()}:"
        out += self.stringify_config()
        out += f"\n\trun_count={self.run_count}"
        if self.run_count > 0:
            out += f"\nfailures="
            out += self.stringify_failures()
        return out

    def delta_list(self):
        out = []
        parent = self
        while parent is not None and parent.parent_delta is not None:
            out.append(str(parent.parent_delta))
            parent = parent.parent
        return ", ".join(out[::-1])

def generate_child_nodes(node: Node, global_state) -> List[Tuple[Node, str, float]]:
    '''
    Return a list of child configs as tuples (config, string representing change, weight of change)
    '''
    # SPECIAL CASE FOR FIRST GENERATION ONLY
    # First generation will have no igloo_init. If we see that, we'll create child configs
    # with each of the potential inits we've identified. That's all we'll do!
    # It's our "opening move" in this game
    children = []  # Tuples of (yaml, delta str)
    if 'igloo_init' not in node.config['env']:
        for init in global_state.inits:
            child = deepcopy(node.config)
            child['env']['igloo_init'] = init
            children.append((child, (("init", init, 1)), 1))
        return children

    # NORMAL CASE: We've previously run node - if it has some failures, we can consider
    # mitigating thse using info from our global state plus our plugins.

    mitigation_providers = get_mitigation_providers(node.config)

    for failure_type, failures in node.failures.items():
        if failure_type not in global_state.failures.keys():
            logger.warning(f"Unmigitiable failure type {failure_type}")
            continue
        if failure_type not in mitigation_providers:
            logger.warning(f"No mitigation proivder for {failure_type}")
            continue

        for fail_cause, fail_info in failures.items():
            #Earlier we called self.global_state.add_mitigation(analysis.ANALYSIS_TYPE, fail_cause, m)
            # so can we just look up the mitigations for this failure?
            for m in global_state.mitigations[failure_type][fail_cause]:
                #print("MITIGATION:", failure_type, fail_cause, m)
                new_config = mitigation_providers[failure_type].implement_mitigation(node.config, fail_cause, m)
                children.append((new_config, ((failure_type, fail_cause, m)), m['weight']))

            '''
            print("Generating child nodes to mitigate", failure_type, fail_cause, fail_info)
            for m in mitigation_providers[failure_type].get_potential_mitigations(node.config, fail_cause, fail_info, global_state.results, global_state.results_lock):
                #print("MITIGATION:", failure_type, fail_cause, m)
                new_config = mitigation_providers[failure_type].implement_mitigation(node.config, fail_cause, m)
                children.append((new_config, ((failure_type, fail_cause, m)), m['weight']))
            '''

    return children

class MCTS:
    '''
    This is our mcts class
    '''
    def __init__(self, initial_config, global_state):
        self.global_state = global_state
        self.config_tree = Node(initial_config)
        self.lock = Lock()
        self.pending_nodes = set()
        self.max_objectives = {k: 1.0 for k in SCORE_CATEGORIES} # Initialized to 1 to avoid division by zero errors

        # On construction, expand our initial config. Initial config is a root node with no igloo_init, and we need
        # children that have it set for us to run. If we ever have only 1 potential value, we'll just have a single
        # child and that will be okay
        if 'igloo_init' not in self.config_tree.config['env']:
            self.config_tree.run_count = 1 # Say we ran the node since we're now done with it
            self.expand(self.config_tree)

    def run_next_task(self, func):
        """
        Selects the next task using MCTS.
        """
        # Starting at the root node of your configuration tree
        node = self.config_tree

        # 1. Selection: Traverse the tree to select the most promising leaf node

        # We hold the lock between finding and adding to pending to make sure
        # we never select the same node twice between multiple threads
        with self.lock:
            node = self.find_best_leaf(node)
            self.pending_nodes.add(node)

        if not node:
            # Can't find a node. We could be done. Or we could be waiting for other workers to finish
            return None

        # Run the selected node
        # Get back a dictionary of {score_type: score}

        node_scores, run_idx = func(node, self.config_tree) # Func == analyze_one
        if not node_scores:
            raise ValueError(f"Failed to run: No return values from {func}")
        node.total_objectives = sum(node_scores.values())

        # After we ran the node, we should now have some failures
        # Expand the node to try mitigating these
        self.expand(node)

        # Optimization: combine child configs
        #self.group(node)


        # 4. Backpropagation: Update the node and its ancestors
        #self.backpropagate(node, node_scores)

        # Return something so we know we did work
        return True

    #def normalize_and_update_ucb1(self, node):
    #    node.normalized_objectives = {k: v / self.max_objectives[k] for k, v in node.objectives.items()}

    def expand(self, node: Node) -> None:
        # Generate child configurations based on node.config and global_state
        child_configs = generate_child_nodes(node, self.global_state)
        for (config, delta, weight) in child_configs:
            child_node = Node(config, parent=node, delta=delta, weight=weight)
            if node.add_child_if_new(child_node):
                pass # Added

    def group(self, node: Node) -> None:
        '''
        Given a node, look at all its children and group together any that are compatible
        For now, we just consider grouping file mitigations together

        DISABLED FOR NOW
        '''
        mitigation_providers = get_mitigation_providers(node.config)

        # Collect a set of mitigations for all files - just pick the first we see for each file
        # Name -> results. We can look up name in mitigation_providers to get the analysis object
        mitigations = {k: [] for k in mitigation_providers.keys()}
        seen_fails = {k: set() for k in mitigation_providers.keys()}

        for child in node.children:
            # How did this child node change from its parent?
            if len(child.parent_delta) != 3:
                # Must be an INIT? probably want to better future-poof this
                continue

            (typ, fail, mitigation) = child.parent_delta
            if fail not in seen_fails[typ]:
                seen_fails[typ].add(fail)
                mitigations[typ].append((fail, mitigation))

        grps = []
        for grp_typ, data in mitigations.items():
            if len(data) < 2:
                # If we only had a single thing, we don't want to make a group
                continue

            # Now let's create one new node based on parent with all thee non-conflicting mitigations applied
            total_weight = 0
            config = deepcopy(node.config)
            delta = []
            for (fail, mitigation) in data:
                analysis = mitigation_providers[grp_typ]
                config = analysis.implement_mitigation(config, fail, mitigation)
                delta.append((grp_typ, fail, mitigation))
                total_weight += mitigation['weight']
            grps.append(config)

            child_node = Node(config, parent=node, delta=delta, is_group=True, weight=total_weight)
            node.add_child_if_new(child_node)

    def find_best_leaf(self, node):
        best_nodes = self.find_leaf_nodes(node, unrun=True) # Find unrun leaves
        if not best_nodes:
            # No leaves
            return None

        # Find highest weight across all leavs
        best_weight = max([n.weight for n in best_nodes])

        # If there are ties, select randomly, otherwise select the best
        best_nodes = [n for n in best_nodes if n.weight == best_weight]
        best = choice(best_nodes)

        return best

    def find_leaf_nodes(self, node, unrun=True):
        if not node.children:
            rv = [node] if node.run_count == 0 and unrun else []
        else:
            rv = [n for c in node.children for n in self.find_leaf_nodes(c)]
        # Remove anythiung that's pending (if unrun)
        if unrun:
            rv = [n for n in rv if n not in self.pending_nodes]
        return rv

    '''
    def calculate_ucb1(self, parent, child):
        C = 1.414  # exploration parameter, tweak based on your needs
        if child.visits == 0:
            return child.weight # Huristic telling us how good we expect this child to be. Hopefully only compared against other weights, not UCB1 scores?

        total_score = sum(child.normalized_objectives.values())  # Sum of normalized objectives - should we take a max? Avg?
        avg_score = total_score / child.visits  # X / n
        exploration_term = math.sqrt((2.0 * math.log(child.visits)) / child.visits)
        return avg_score + C * exploration_term
    '''


    '''
    def backpropagate(self, node, scores):
        # First update max_objectives as necessary for each objective
        for name, value in scores.items():
            self.max_objectives[name] = max(self.max_objectives[name], value)

        # Then update the scores for this node and its ancestors
        current_node = node
        while current_node is not None:
            with current_node.lock:
                current_node.visits += 1
                for k, v in scores.items():
                    node.objectives[k] += v
            current_node = current_node.parent
    '''

    def uct_value(self, parent_visits, node):
        """
        Calculate UCT value for a given node.
        """
        if node.visits == 0:
            return float('inf')
        exploitation_value = node.value / node.visits
        exploration_value = math.sqrt(math.log(parent_visits) / node.visits)

        group_bonus = 100 if node.is_group else 0
        return exploitation_value + exploration_value + group_bonus

    def select_node(self, node):
        """
        Perform MCTS-based node selection starting from the given node.
        """
        best_value = -1
        best_node = None
        for child in node.children:
            node_value = self.uct_value(node.visits, child)
            if node_value > best_value:
                best_value = node_value
                best_node = child
        return best_node

class GlobalState:
    def __init__(self, output_dir, base_config):
        self.output_dir = output_dir

        # Store global information from our config

        # show_output is False unless we're told otherwise
        show_output = base_config['core']['show_output'] \
            if 'show_output' in base_config['core'] else False

        # root_shell is True unless we're told otherwise
        root_shell = base_config['core']['root_shell'] \
                if 'root_shell' in base_config['core'] else True

        self.info ={
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

        self.results_lock = Lock()
        self.results = {} # {analysis_name: {data}}
                        # 'env': varname -> set strings compared against
                        # 'pseudofiles': (filename, ioctl num) -> set of retvals


        self.failures_lock = Lock()
        self.failures = {}

        self.mitigations_lock = Lock()
        self.mitigations = {}

        # Setup global data
        self.initialize_from_static_results(base_config)

    def initialize_from_static_results(self, base_config):
        '''
        Static analysis will populate some fields, "potential_*". Unlike our regular model, we haven't observed
        any dynamic events around them, but we're going to use our static analysis to populate some potential failures
        and identify potential mitigations right away.
        '''

        # Look through potential_{files,env} and use plugins to initialize mitigations
        mitigation_providers = get_mitigation_providers(base_config)

        for plugin_name, analysis in mitigation_providers.items():
            with self.failures_lock:
                self.failures[analysis.ANALYSIS_TYPE] = {}

            # We have some static info in files and env to try!
            data = []

            # We have no real failures, but given the potential failures we've statically identified
            # we can start by proposing some mitigations for these already!
            # Dict with key->potential_mitigation (e.g., env vars with known potential values)
            # or list with just keys (e.g., device filenames that are missing)
            for k, known_vals in (data if isinstance(data, dict) else {k: [] for k in data}).items():
                # Record the (potential) failure type: e.g., an environment variable or a filename
                self.add_failure(analysis.ANALYSIS_TYPE, k) # E.g., (file, /dev/missing)

                # If our static analysis gave us some potential values, include these first
                for m in analysis.get_mitigations_from_static(k, known_vals):
                    self.add_mitigation(analysis.ANALYSIS_TYPE, k, m)

    def __repr__(self):
        out = f"GlobalState: \n"
        with self.failures_lock:
            for k, v in self.failures.items():
                out += "\t" + k + ":\n"
                if isinstance(v, dict):
                    for itemk, item in v.items():
                        out += f"\t\t{itemk} = {item}\n"
                elif isinstance(v, list):
                    for item in v:
                        out += f"\t\t{item}\n"
        return out

    def add_failure(self, fail_type, fail_cause, fail_info=None):
        # in failures[fail_type] we make room for fail_cause and store fail_info if we have any
        '''
        Add a new failure to our global state. E.g., in the file state, we have filename -> [potential mitigations]

        # fail_type = pseudofiles
        # failure = "/some/filename":
        # fail_info = {syscall: {count: X}}

        # fail_type = env
        # XXX UNSURE
        '''
        with self.failures_lock:
            if fail_type not in self.failures.keys():
                raise ValueError(f"add_failure: {fail_type} type unknown")

            if fail_cause not in self.failures[fail_type]:
                self.failures[fail_type][fail_cause] = []

            if fail_info and fail_info not in self.failures[fail_type][fail_cause]:
                self.failures[fail_type][fail_cause].append(fail_info)

    def add_mitigation(self, fail_type, failure, mitigation):
        '''
        Store a mitigation. If we get something identical to a prior mitigation with a different weight
        we just update the weight if it's higher. Idk man.

        mitigations[fail_type][failure][mitigation] = [{*, weight: X}, {*, weight: Y}]
        '''
        if not isinstance(mitigation, dict):
            raise ValueError(f"add_mitigation: mitigation must be a dict, but got {mitigation}")

        if not 'weight' in mitigation or not isinstance(mitigation['weight'], float):
            raise ValueError(f"add_mitigation: mitigation must have a float weight, but got {mitigation}")

        # We must have seen this failure before we add a mitigation for it
        if fail_type not in self.failures:
            raise ValueError(f"add_mitigation: {fail_type} type unknown")
        if failure not in self.failures[fail_type]:
            raise ValueError(f"add_mitigation: {fail_type} failure: {failure} unknown")

        with self.mitigations_lock:
            if fail_type not in self.mitigations:
                # It was in self.failures so we're good to add it
                self.mitigations[fail_type] = {}

            if failure not in self.mitigations[fail_type]:
                # It was in self.failures so we're good to add it
                self.mitigations[fail_type][failure] = []

            # We just got a dict, we want to know if this mitigation is already in our list
            # If so, we want to update the weight if it's higher
            new_weight = mitigation['weight']
            new_weightless = {k: v for k, v in mitigation.items() if k != 'weight'}

            # Look through all existing mitigations while ignoring weight
            for existing in self.mitigations[fail_type][failure]:
                existing_weight = existing['weight']
                existing_weightless = {k: v for k, v in existing.items() if k != 'weight'}
                if new_weightless == existing_weightless:
                    # We've seen this mitigation before
                    if new_weight > existing_weight:
                        # And this one has a higher weight - update it
                        existing['weight'] = new_weight
                    return

            # If we get here, we haven't seen this mitigation before
            self.mitigations[fail_type][failure].append(mitigation)

class Worker:
    def __init__(self, mcts, global_state, run_base, max_iters, run_index, active_worker_count):
        self.mcts = mcts
        self.global_state = global_state
        self.run_base = run_base
        self.max_iters = max_iters
        self.run_index = run_index
        self.active_worker_count = active_worker_count

    def run(self):
        while self.max_iters == -1 or self.run_index.get() < self.max_iters:
            # Fetch a config to run

            self.active_worker_count.increment()
            config = self.mcts.run_next_task(self.analyze_one)
            self.active_worker_count.decrement()

            if config is None:
                time.sleep(1)
                # If all workers are waiting, that means we're done
                if self.active_worker_count.get() == 0:
                    logger.info("All workers waiting, exiting")
                    break
                continue


    def analyze_one(self, node, config_tree_debug_only, n_config_tests=1):
        '''
        Run a given configuration, collect details of it's failures. Return score
        '''
        #print(f"Doing analyze_one for {node}")
        run_idx = self.run_index.increment()
        run_dir = os.path.join(self.run_base, str(run_idx))
        if os.path.isdir(run_dir):
            # Remove it
            shutil.rmtree(run_dir)
        os.makedirs(run_dir)

        node.run_idx = run_idx

        # Write config to disk
        combined_config = deepcopy(node.config)
        combined_config['core'] = self.global_state.info
        dump_config(combined_config, os.path.join(run_dir, "config.yaml"))

        # *** EMULATE TARGET ***
        #print(f"Start run {run_idx}: with config at {run_dir}/config.yaml")
        this_logger = logging.getLogger(f"run{run_idx}")
        this_logger.info(f"Derived from {node.parent.run_idx if node.parent else 'N/A'} with {node.parent_delta}")

        # Run emulation `n_config_tests` times. If any error, print the error
        for config_idx in range(n_config_tests):
            try:
                self._run_config(run_dir, n=config_idx)
            except RuntimeError as e:
                # Uh oh, we got an error while running. Warn and continue
                logger.warning(f"Error running {run_dir}")
                return None, None
            finally:
                node.run_count += 1

        scores = self.find_best_score(run_dir, run_idx, n_config_tests, this_logger)
        self.analyze_failures(run_dir, run_idx, node, n_config_tests, this_logger)

        #print(f"After run {run_idx}: {node}")

        G = config_tree_to_networkx_graph(config_tree_debug_only)
        nx.write_graphml(G, os.path.join(run_dir, f"config_tree.graphml"))

        return scores, run_idx

    def analyze_failures(self, run_dir, run_idx, node, n_config_tests, this_logger):
        '''
        After we run a configuration, do our post-run analysis of failures.
        Run each PyPlugin that has a PenguinAnalysis implemented. Have each
        identify failures and store these in our global state of know failures
        (global_state.add_failures) as well as a failure for this config
        (config.add_config_failures). Write down all the faiulres in failures.txt
        within run_dir.

        Plugins are allowed to store arbitrary data in a global cache as an optimization
        for future runs. This is stored in global_state.results[plugin_name]

        For each identified failure, ask the plugin to propose mitigations. Add
        these to the global mitigation state with global_state.add_mitigation

        TODO: Focus on analysis delta from parent and score delta instead of total score?
        '''

        for config_idx in range(n_config_tests):
            output_dir = os.path.join(run_dir, f"output{config_idx}" if config_idx > 0 else "output")

            # For each loaded plugin, analyze output and update local/global state
            failures = {}
            all_fails = []

            mitigation_providers = get_mitigation_providers(node.config)
            for plugin_name, analysis in mitigation_providers.items():
                try:
                    failures = analysis.parse_failures(output_dir, self.global_state.results, self.global_state.results_lock)
                except Exception as e:
                    this_logger.error(e)
                    raise e

                if len(failures):
                    this_logger.info(f"Plugin {plugin_name} reports {len(failures)} failures: {list(failures.keys())}")

                # Failures is a dict like 
                # {filename: {failing_syscall: {count: X}}
                # OR for IOCTLS {filename: {ioctl: {ioctl_num: {count: X}}}

                for fail_cause, fail_info in failures.items():
                    # fail_cause is a tuple of (filename, syscall) or (filename, ioctl, ioctl_num).
                    # fail_info is an arbitrary object we store from the plugin on failure detection that we pass through to mitigations
                    # e.g., potential ioctl return values
                    all_fails.append((analysis.ANALYSIS_TYPE, fail_cause))

                    #if fail_cause in config.config[analysis.ANALYSIS_TYPE]:
                    #    # This config already has a mitigation for this failure - can't add again
                    #    raise RuntimeError(f"BUG: {fail_cause} is a failure and a mitigation, returned by {analysis}'s parse_failures")

                    node.add_config_failure(analysis.ANALYSIS_TYPE, fail_cause, fail_info) # This only stores the latest fail_info. HMM XXX TODO?
                    self.global_state.add_failure(analysis.ANALYSIS_TYPE, fail_cause, fail_info) # This stores a list of fail_info

                    # get_mitigations is told the info of the failure, but add_mitigation doesn't need that
                    for m in analysis.get_potential_mitigations(node.config, fail_cause, fail_info, self.global_state.results, self.global_state.results_lock) or []:
                        self.global_state.add_mitigation(analysis.ANALYSIS_TYPE, fail_cause, m)

            with open(os.path.join(output_dir, "failures.txt"), "a") as f:
                for (analysis_type, fail) in all_fails:
                    f.write(f"{analysis_type}: {fail}\n")
                    # Get mitigations out of global state and log these as well
                    mits = self.global_state.mitigations[analysis_type][fail]
                    for m in mits:
                        f.write(f"\t{m}\n")

    def find_best_score(self, run_dir, run_idx, n_config_tests, this_logger):
        '''
        Look acrous our `n_config_tests` runs. Calculate the maximal score for each
        score type our various metrics
        '''
        best_scores = {} # For each key, maximal score across all runs
        for config_idx in range(n_config_tests):
            these_scores = self.calculate_score(os.path.join(run_dir, f"output{config_idx}" if config_idx > 0 else "output"))
            for score_name, score in these_scores.items():
                if score_name not in best_scores or score > best_scores[score_name]:
                    best_scores[score_name] = score

        # Report scores and save to disk
        this_logger.info(f"Run scores: {[f'{k[:4]}:{v}' for k, v in best_scores.items()]}")
        with open(os.path.join(run_dir, "scores.txt"), "w") as f:
            f.write("score_type,score\n")

            for k, v in best_scores.items():
                f.write(f"{k},{v:.02f}\n")

        # Write a single score to disk
        with open(os.path.join(run_dir, "score.txt"), "w") as f:
            total_score = sum(best_scores.values())
            f.write(f"{total_score:.02f}")

        return best_scores

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

        # Coverage: processes, modules, blocks
        with open(f"{result_dir}/coverage.csv") as f:
            # XXX no header, but it's process, module, offset. No index either
            df = pd.read_csv(f, header=None, names=['process', 'module', 'offset'], index_col=False)

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

        score = {
            'execs': health_data['nexecs'],
            'bound_sockets': health_data['nbound_sockets'],
            'devices_accessed': health_data['nuniquedevs'],
            'processes_run': df['process'].nunique(),
            'modules_loaded': df['module'].nunique(),
            'blocks_covered': df.drop_duplicates(subset=['module', 'offset']).shape[0], # Count of unique (module, offset) pairs
            'nopanic': 1 if not panic else 0,
        }

        for k in score.keys():
            if k not in SCORE_CATEGORIES:
                raise ValueError(f"BUG: score type {k} is unknown")
        return score

    def _run_config(self, run_dir, n=0):
        '''
        Given a run_dir which contains a config.yaml, do a run and store output
        in the output{n} subdirectory.
        '''
        conf_yaml = os.path.join(run_dir, "config.yaml")
        out_dir = os.path.join(run_dir, "output" + (str(n) if n > 0 else ""))
        os.makedirs(out_dir, exist_ok=True)
        self._subprocess_panda_run(conf_yaml, run_dir, out_dir)

    def _subprocess_panda_run(self, conf_yaml, run_dir, out_dir):
        # penguin_run will run panda directly which might exit (or crash/hang)
        # so we run it in a subprocess to maintain control
        # Calls penguin_run.py's run_config method
        # Wrapper to call run_config(config=argv[1], out=argv[2], qcows=argv[3])

        cmd = [ "python3", "-m", "penguin.penguin_run",
                conf_yaml,
                out_dir,
                self.run_base + "/qcows"
                ]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate() # Wait for termination
        except Exception as e:
            logger.error(f"An exception occurred launching {cmd}: {str(e)}")
            #raise e
            return

        with open(os.path.join(out_dir, "qemu_stdout.txt"), "w") as f:
            f.write(stdout)
        with open(os.path.join(out_dir, "qemu_stderr.txt"), "w") as f:
            f.write(stderr)

        # Let it exit 0 or exit with 120 if it's a bad file descriptor (python gets sad when stdio closes)
        if process.returncode != 0 and not (process.returncode == 120 and "Bad file descriptor" in stderr):
            logger.error(f"Error running {cmd}: Got return code {process.returncode}")
            logger.error(f"stdout: {stdout}")
            logger.error(f"stderr: {stderr}")

        # Check if we have the expected .ran file in output directory
        ran_file = os.path.join(out_dir, ".ran")
        if not os.path.isfile(ran_file):
            logger.error(f"Missing .ran file with {conf_yaml}")
            raise RuntimeError(f"ERROR, running {conf_yaml} in {run_dir} did not produce {out_dir}/.ran file")

def config_tree_to_networkx_graph(root_config):
    """
    Converts a Node tree to a NetworkX directed graph.
    :param root_config: The root node of the Node tree
    :return: A NetworkX DiGraph object
    """
    G = nx.DiGraph()

    def dfs(config_node, parent_node=None):
        #node_label = config_node.delta_list()  # Replace with your preferred node label
        node_label = config_node.label()
        G.add_node(node_label, data=config_node.stringify_config(), failures=config_node.stringify_failures(), score=config_node.total_objectives)

        if parent_node is not None:
            edge_label = str(config_node.parent_delta)  # Replace with your preferred edge label
            G.add_edge(parent_node, node_label, label=edge_label)

        for child in config_node.children:
            dfs(child, node_label)

    dfs(root_config)
    return G

def iterative_search(initial_config, output_dir, max_iters=1000, n_workers=10, MULTITHREAD=True):
    '''
    Main entrypoint. Given an initial config and directory, iteratively search
    for modifications and a revised config
    '''

    run_index = AtomicCounter(0)
    active_worker_count = AtomicCounter(0)

    global_state = GlobalState(output_dir, initial_config)
    mcts = MCTS(initial_config, global_state)

    run_base = os.path.join(output_dir, "runs")
    os.makedirs(run_base, exist_ok=True)

    if MULTITHREAD:
        worker_threads = []
        for _ in range(n_workers):
            worker_instance = Worker(mcts, global_state,
                                        run_base, max_iters, run_index, active_worker_count)
            t = Thread(target=worker_instance.run)
            t.start()
            worker_threads.append(t)

        # Wait for all threads to finish
        for t in worker_threads:
            t.join()
    else:
        # Single-threaded
        worker_instance = Worker(mcts, global_state,
                                run_base, max_iters, run_index,
                                active_worker_count)
        worker_instance.run()


def main():
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <config> <outdir>")
        sys.exit(1)

    config = load_config(sys.argv[1])
    iterative_search(config, sys.argv[2], MULTITHREAD=False)

if __name__ == '__main__':
    main()