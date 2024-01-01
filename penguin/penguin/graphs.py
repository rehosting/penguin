import networkx as nx
import matplotlib.pyplot as plt
import pickle
from typing import Optional, List, Callable, Tuple

class GraphNode:
    '''
    Base class for all graph nodes
    '''
    def __init__(self, id, node_type):
        self.id = id
        self.node_type = node_type

    def __repr__(self):
        return f"{self.node_type}({self.id})"

    def to_dict(self):
        return {"id": self.id, "type": self.node_type}
    
class Configuration(GraphNode):
    def __init__(self, id, properties):
        '''
        A configuration is a key value store of various properties.
        These are the inputs to our target system.
        A configuration will be marked as run=True once we've run it.
        '''
        super().__init__(id, "configuration")
        self.run=False
        self.weight = 1.0
        self.properties = properties


class Failure(GraphNode):
    def __init__(self, id, type, info = None):
        '''
        Failures are observed by running our target system with a given
        config. These are of various types and have a dictionary of info

        The type and info are returned by analysis helpers that examine
        the results of running a config
        '''
        super().__init__(id, "failure")
        self.type = type
        self.info = info if info else {}
        self.weights = []
        self.weight = 1.0 # Default

class Mitigation(GraphNode):
    def __init__(self, id, type, info = None):
        '''
        A mitigation is designed to mitigate an identified failure.
        It has a strategy that can be applied to a configuration that
        tries to mitigate the failure.

        The type/info is passed to a helper function to implement
        the mitigation for a given configuration.
        '''
        super().__init__(id, "mitigation")
        self.type = type
        self.info = info if info else {}


class ConfigurationGraph:
    def __init__(self, base_config: Configuration = None):
        self.graph = nx.DiGraph()
        if base_config:
            self.add_node(base_config)

    def add_node(self, node: GraphNode):
        if not isinstance(node, GraphNode):
            raise TypeError(f"node must be an instance of GraphNode or its subclasses. got {node}")

        if self.graph.has_node(node.id):
            raise ValueError(f"Node with id {node.id} already exists")

        self.graph.add_node(node.id, object=node)

    def has_node(self, node: GraphNode):
        return self.graph.has_node(node.id)

    def add_edge(self, from_node: GraphNode, to_node: GraphNode):
        edge_type = self.determine_edge_type(from_node, to_node)
        if edge_type:
            self.graph.add_edge(from_node.id, to_node.id, type=edge_type, weight=1.0)
        else:
            raise ValueError(f"Invalid edge type between {from_node.node_type} and {to_node.node_type}")

    @staticmethod
    def determine_edge_type(from_node: GraphNode, to_node: GraphNode):
        edge_type_mapping = {
            ('configuration', 'configuration'): 'CC',
            ('configuration', 'failure'): 'CF',
            ('failure', 'mitigation'): 'FM',
            ('mitigation', 'configuration'): 'MC'
        }
        try:
            return edge_type_mapping[(from_node.node_type, to_node.node_type)]
        except KeyError:
            raise ValueError(f"Invalid edge type between {from_node.node_type} and {to_node.node_type}")

    def report_config_run(self, config: Configuration, health_score: float):
        '''
        After we've run a configuration we have its health score.

        For all but the root config, we'll have a chain:
        parent config -> failure -> mitigation -> this config
        and there's also an edge from parent config -> this config
        We make two updates for weight: at parent config -> this config we directly set the weight
        as this edge is only considered once. Then at the failure->mitigation edge we add
        the weight to a list of weights, and update the weight to be the average of the list.
        This is because mitigations are tested multiple times.

        The goal is to tune our weights such that 
        1) From the parent config, we'll be able to select child configs with high health scores
        2) From the failure we'll be able to select mitigations with high health scores
        '''

        # Update node to be run
        self.graph.nodes[config.id]['object'].run = True

        config.health_score = health_score

        # For the initial config, there are no predecessors, so we don't do anything
        # We want to check if this iterator is empty, but it's not subscriptable
        # so we'll just check if it's not empty with next()
        if not next(self.graph.predecessors(config.id), None):
            return

        # We should (must) have a single parent config and a single parent mitigation

        found_parent_config = False
        found_parent_failure = False

        for pred in self.graph.predecessors(config.id):
            if self.graph.nodes[pred]['object'].node_type == 'configuration':
                self.set_cc_edge_weight(pred, config.id, health_score)
                found_parent_config = True

            if self.graph.nodes[pred]['object'].node_type == 'mitigation':
                mitigation_id = pred
                for failure_pred in self.graph.predecessors(mitigation_id):
                    if self.graph.nodes[failure_pred]['object'].node_type == 'failure':
                        # We've now found the failure->mitigation path
                        found_parent_failure = True

                        # Add the weight to weights list. Update weight
                        # We're selecting the failure node XXX: Do we want an edge?
                        weights = self.graph.nodes[failure_pred]['object'].weights
                        weights.append(health_score)
                        self.graph.nodes[failure_pred]['object'].weight = \
                            sum(weights) / len(weights)

        if not found_parent_config:
            raise ValueError(f"Could not find parent config for {config.id}")

        if not found_parent_failure:
            raise ValueError(f"Could not find failure->mitigation path for {config.id}")
    
    def set_cc_edge_weight(self, from_node: str, to_node: str, new_weight: float):
        """
        Set the weight of an edge between two configurations in the graph.

        Args:
            from_node (str): The starting node of the edge.
            to_node (str): The ending node of the edge.
            new_weight (float): The new weight to assign to the edge.
        """
        if not self.graph.has_edge(from_node, to_node):
            raise ValueError("Edge does not exist in the graph.")
        
        # Make sure edge is of type CC
        edge_type = self.determine_edge_type(self.graph.nodes[from_node]['object'], self.graph.nodes[to_node]['object'])
        if edge_type != 'CC':
            raise ValueError(f"Edge between {from_node} and {to_node} is of type {edge_type}, not CC")

        # Make sure there wasn't a prior weight
        if 'weight' in self.graph[from_node][to_node]:
            raise ValueError(f"CC edge between {from_node} and {to_node} already has weight {self.graph[from_node][to_node]['weight']}")
        
        # Finally update the weight
        self.graph[from_node][to_node]['weight'] = new_weight

    def mitigations_for(self, failure):
        '''
        Given a failure, return a list of mitigations that could be applied
        '''
        return [self.graph.nodes[n]['object'] for n in self.graph.successors(failure.id) \
                    if self.graph.nodes[n]['object'].type == 'mitigation' ]

    def add_derived_configuration(self, derived_config: GraphNode, parent_config: GraphNode, mitigation: GraphNode):
        """
        Add a new configuration derived from a specific mitigation and parent configuration.
        """

        if not self.graph.has_node(mitigation.id):
            raise ValueError(f"Mitigation {mitigation} does not exist in the graph.")
        
        if not self.graph.has_node(parent_config.id):
            raise ValueError(f"Parent configuration {parent_config} does not exist in the graph.")

        # derived_config is our new config - this is probably new
        if not self.graph.has_node(derived_config.id):
            self.add_node(derived_config)

        # We need an edge from the mitigation to the new config
        if not self.graph.has_edge(mitigation.id, derived_config.id):
            self.graph.add_edge(mitigation.id, derived_config.id, type='MC')

        # And an edge from the parent config to the new config
        if not self.graph.has_edge(parent_config.id, derived_config.id):
            self.graph.add_edge(parent_config.id, derived_config.id, type='CC')

    def prune_graph(self):
        """
        Prune the graph to remove redundant or fully explored nodes.

        This function removes nodes and edges that are deemed unnecessary for future exploration,
        based on certain criteria like node redundancy or lack of failure links.
        """
        # This is a placeholder for the pruning logic
        pass

    def save_graph(self, file_path: str):
        """
        Save the graph to a file using pickle.

        Args:
            file_path (str): The file path where the graph should be saved.
        """
        if not isinstance(file_path, str):
            raise ValueError("Invalid input type for file_path.")

        with open(file_path, 'wb') as f:
            pickle.dump(self.graph, f)

    def create_png(self, file_path: str):
        """
        Create a PNG image of the graph with enhanced visual features.

        Args:
            file_path (str): The file path where the PNG image will be saved.
        """
        if not isinstance(file_path, str):
            raise ValueError("Invalid input type for file_path.")

        # Colors based on node type (configuration, failure, mitigation) or edge type (CF, FC, CC)
        node_colors = {
            "configuration": "lightblue",
            "failure": "lightcoral",
            "mitigation": "lightyellow",
        }
        edge_colors = {"CF": "black", "FC": "black", "CC": "green"}
        edge_styles = {"CF": "dotted", "FC": "dotted", "CC": "solid"}

        colors = [node_colors.get(self.graph.nodes[node]['object'].node_type, 'lightgray') for node in self.graph.nodes]
        edge_colors = [edge_colors.get(self.graph.edges[edge]['type'], 'black') for edge in self.graph.edges]
        edge_styles = [edge_styles.get(self.graph.edges[edge]['type'], 'solid') for edge in self.graph.edges]

        #pos = nx.nx_agraph.graphviz_layout(self.graph, prog='dot')

        # Calculate the figure size dynamically based on the number of nodes
        num_nodes = len(self.graph.nodes())
        figure_size = max(8, num_nodes / 3)  # Adjust the denominator for scaling

        plt.figure(figsize=(figure_size, figure_size))

        # Use a layout algorithm to space out the nodes
        # pos = nx.spring_layout(self.graph)  # Alternative layout
        pos = nx.nx_agraph.graphviz_layout(self.graph, prog='dot')


        nx.draw(self.graph, pos, with_labels=True, node_color=colors, 
                edge_color=edge_colors, style=edge_styles, node_size=2500, font_size=10, arrowsize=20)

        # Draw edge labels for FM edges
        for u, v, d in self.graph.edges(data=True):
            print(f"Edge from {u} to {v} of type {d['type']}. Weight: {d.get('weight', 'NA')}")

        fm_edge_labels = {(u, v): f"{d['weight']}" for u, v, d in self.graph.edges(data=True) if d['type'] == 'FM'}
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=fm_edge_labels, font_color='green')

        plt.savefig(file_path)
        plt.close()

    def find_unexplored_configurations(self) -> List[str]:
        """
        Find all configurations that have not been run yet.

        Returns:
            list: A list of configuration IDs that have not been linked to any failures or mitigations.
        """
        unexplored = [node for node, attrs in self.graph.nodes(data=True) 
                    if attrs['object'].node_type == 'configuration' and \
                         not self.graph.nodes[node]['object'].run ]
        return unexplored

    def get_node(self, node_id: str) -> GraphNode:
        """
        Get a node from the graph.

        Args:
            node_id (str): The ID of the node to retrieve.

        Returns:
            GraphNode: The node with the given ID.
        """
        if not isinstance(node_id, str):
            raise ValueError("Invalid input type for node_id.")

        if not self.graph.has_node(node_id):
            raise ValueError(f"Node with ID {node_id} does not exist in the graph.")

        return self.graph.nodes[node_id]['object']

class ConfigurationManager:
    def __init__(self, base_config : Configuration,
                    run_config_f : Callable[[Configuration], Tuple[List[Failure], float]],
                    find_mitigations_f: Callable[[Failure, Configuration], List[Mitigation]],
                    find_new_configs_f: Callable[[Failure, Mitigation],
                                                 List[Tuple[Configuration, Configuration]]]):
        '''
        A configuration manager manages exploration of a ConfigurationGraph
        consistings of Configurations, Failures, and Mitigations.

        In this graph, Configurations have children of failures and new configurations.
        Failures have children of mitigations. Mitigations have children of
        new configurations. Configurations are either run or un-run.
        By running a configuration, we can dynamically identify new failures.
        These failures can then be mitigated by applying a mitigation which
        produces a new configuration. New configurations are connected back to
        the original configuration that was run, and the mitigation that was applied.

        We dynamically learn/adjust weights for edges in the graph based on
        the health score of a configuration.

        In particular: 

        The graph is initialized with a base config which has not been run,
        and a set of user-provided functions to use during exploration.

        A user can drive exploration by calling run_exploration_cycle() which
        will select the best un-run config and pass it to the provided
        run_config_f. This function is responsible for evaluating the config
        (i.e., running it) and identifying failures and a health score.
        The graph will be updated to indicate that the config has been run
        and its health score.

        Each (new) identified failure will be added to the graph.

        For each failure, we'll call find_mitigations_f to get a list of mitigations
        that could be applied to mitigate the failure. Each mitigation will be added
        to the graph.
        '''

        self.graph = ConfigurationGraph(base_config)

        self.run_config_f = run_config_f
        self.find_mitigations_f = find_mitigations_f
        self.find_new_configs_f = find_new_configs_f


    def run_configuration(self, config : Configuration):
        """
        Run a given configuration to get a list of failure and a health score.
        Update the graph with the new information to set weights
        Add new failures and mitigations to the graph
        """

        print(f"Run config: {config}")

        failures, health_score = self.run_config_f(config)

        # Sets run, health(?), and updates weights
        self.graph.report_config_run(config, health_score)

        # Now we add new failures that we observed during this run
        for failure in failures:
            if not self.graph.has_node(failure):
                print("Found new failure:", failure)
                self.graph.add_node(failure)
            self.graph.add_edge(config, failure)

            # Now for each of these failures, let's see if there are new mitigations
            # we could apply. We know the configuration that was run, and the failure.
            # Note the failure might not be new, but perhaps the mitigation is
            for mitigation in self.find_mitigations_f(failure, config):
                if not self.graph.has_node(mitigation):
                    print("ADDED MITIGATION W ID", mitigation.id)
                    self.graph.add_node(mitigation)

                # Edge should be new? Maybe not
                self.graph.add_edge(failure, mitigation)

            # Now look at the mitigations for this failure, and see if there are any new configurations
            # we could derive from them.
            #self.find_configs_from_failure(failure)

            for mitigation in self.graph.mitigations_for(failure):
                for derived_from, config in self.find_new_configs_f(failure, mitigation):
                    # Add new config derived from this mitigation
                    #print("Found new config as mitigation for failure:", failure, config)
                    self.graph.add_derived_configuration(config, derived_from, mitigation)

    def run_exploration_cycle(self):
        """ Get the best config and run it """
        if config_to_run := self.select_best_config():
            self.run_configuration(config_to_run)
            return config_to_run

        print("No more configurations to run")
        return None

    def select_best_config(self) -> Optional[Configuration]:
        """
        Select the best configuration to run next. Node can't have been run before

        Just return the first unexplored config for now
        TODO: select based on weight and health score
        we'd want to take config weights + mitigation weights into account
        to identify an un-run config with the highest expected health score
        """

        unexplored = self.graph.find_unexplored_configurations()
        if len(unexplored) > 0:
            return self.graph.get_node(unexplored[0])
        return None

def main():
    base_config = Configuration("config_0", {"some_data": "some_value"})

    def run_config(config : Configuration) -> Tuple[List[Failure], float]:
        '''
        Stub implementation of running a config.
        Return a tuple of [failures], health_score
        '''

        stubs = {
            "config_0": {
                "failures":
                    [Failure("failure_A", "stub", {"some_data": "some_value"}),
                     Failure("failure_B", "stub", {"some_data": "other_value"})],
                "health_score": 50
            },
            "config_A0": {
                "failures":
                    [Failure("failure_B", "stub", {"some_data": "other_value"})],
                "health_score": 60
            },
            "config_A1": {
                "failures":
                    [Failure("failure_A", "stub", {"some_data": "some_value"})],
                "health_score": 30
            },
            "config_B0": {
                "failures":
                    [Failure("failure_A", "stub", {"some_data": "some_value"})],
                "health_score": 100
            },
            "config_B1": {
                "failures":
                    [Failure("failure_B", "stub", {"some_data": "other_value"})],
                "health_score": 30
            },
            "config_C": {
                "failures": [],
                "health_score": 3000
            }
        }

        try:
            return stubs[config.id]["failures"], stubs[config.id]["health_score"]
        except KeyError:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {config}")

    def find_mitigations_f(failure, config):
        '''
        Given a failure and a config, identify mitigations that could be applied.
        This should be deterministic - if two failures have the same mitigations
            they should produce the same mitigations - but the data may be distinct.
            Graph will need to combine the data
        '''
        if failure.id == "failure_A":
            return [Mitigation("mitigation_A0", "mitigation", {"some_data": "some_value"}),
                    Mitigation("mitigation_A1", "mitigation", {"some_data": "other_value"})]
        elif failure.id == "failure_B":
            return [Mitigation("mitigation_B0", "mitigation", {"some_data": "some_value"}),
                    Mitigation("mitigation_B1", "mitigation", {"some_data": "other_value"})]
        elif failure.id == "failure_C":
            return []
        else:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {failure}")

    def find_new_configs_f(failure, mitigation):
        '''
        Given a failure and a mitigation, find any new configurations that could be derived from them.
        Returns tuples of (derived_from, config_id)
        '''
        # STUB
        if failure.id == 'failure_A':
            if mitigation.id == 'mitigation_A0':
                return [(Configuration("config_0", {"some_data": "some_value"}),
                         Configuration("config_A0", {"some_data": "some_value"}))]

            elif mitigation.id == 'mitigation_A1':
                return [(Configuration("config_0", {"some_data": "some_value"}),
                         Configuration("config_A1", {"some_data": "some_value"}))]

        elif failure.id == 'failure_B':
            if mitigation.id == 'mitigation_B0':
                return [(Configuration("config_0", {"some_data": "some_value"}),
                         Configuration("config_B0", {"some_data": "some_value"}))]
            elif mitigation.id == 'mitigation_B1':
                return [(Configuration("config_0", {"some_data": "some_value"}),
                         Configuration("config_B1", {"some_data": "some_value"})),
                        (Configuration("config_A0", {"some_data": "some_value"}),
                         Configuration("config_C", {"some_data": "some_value"})) ]
        return []



    config_manager = ConfigurationManager(base_config, run_config, find_mitigations_f,
                                        find_new_configs_f)

    # Run a series of exploration cycles
    for _ in range(15):  # Adjust the range as needed for testing
        if not config_manager.run_exploration_cycle():
            break

    # Visualize the resulting graph
    config_manager.graph.create_png("/results/config_graph.png")

if __name__ == "__main__":
    main()