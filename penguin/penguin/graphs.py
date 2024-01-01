import networkx as nx
import matplotlib.pyplot as plt
import pickle

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
        self.properties = properties
        self.run=False
        self.weight = 1.0

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
            raise TypeError("node must be an instance of GraphNode or its subclasses")

        if self.graph.has_node(node.id):
            raise ValueError(f"Node with id {node.id} already exists")

        self.graph.add_node(node.id, type=node.node_type, properties=node.to_dict())

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

        config.health_score = health_score

        # For the initial config, there are no predecessors, so we don't do anything
        if self.graph.predecessors(config.id) == []:
            return

        # We should (must) have a single parent config and a single parent mitigation

        found_parent_config = False
        found_parent_failure = False

        for pred in self.graph.predecessors(config.id):
            if self.graph.nodes[pred]['type'] == 'configuration':
                self.set_cc_edge_weight(pred, config.id, health_score)
                found_parent_config = True

            if self.graph.nodes[pred]['type'] == 'mitigation':
                mitigation_id = pred
                for failure_pred in self.graph.predecessors(mitigation_id):
                    if self.graph.nodes[failure_pred]['type'] == 'failure':
                        # We've now found the failure->mitigation path
                        found_parent_failure = True

                        # Add the weight to weights list
                        self.graph[failure_pred][mitigation_id]['weights'].append(health_score)

                        # Update weight to be average
                        self.graph[failure_pred][mitigation_id]['weight'] = \
                            sum(self.graph[failure_pred][mitigation_id]['weights']) / \
                            len(self.graph[failure_pred][mitigation_id]['weights'])

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
        edge_type = self.determine_edge_type(self.graph.nodes[from_node], self.graph.nodes[to_node])
        if edge_type != 'CC':
            raise ValueError(f"Edge between {from_node} and {to_node} is of type {edge_type}, not CC")

        # Make sure there wasn't a prior weight
        if 'weight' in self.graph[from_node][to_node]:
            raise ValueError(f"CC edge between {from_node} and {to_node} already has weight {self.graph[from_node][to_node]['weight']}")
        
        # Finally update the weight
        self.graph[from_node][to_node]['weight'] = new_weight

    def mitigations_for(self, failure_id):
        '''
        Given a failure, return a list of mitigations that could be applied
        '''
        return [n for n in self.graph.successors(failure_id) if self.graph.nodes[n]['type'] == 'mitigation' ]

    def add_derived_configuration(self, derived_config: GraphNode, parent_config: GraphNode, mitigation: GraphNode):
        """
        Add a new configuration derived from a specific mitigation and parent configuration.
        """

        if not self.graph.has_node(mitigation):
            raise ValueError(f"Mitigation {mitigation} does not exist in the graph.")
        
        if not self.graph.has_node(parent_config):
            raise ValueError(f"Parent configuration {parent_config} does not exist in the graph.")

        # derived_config is our new config
        if not self.graph.has_node(derived_config):
            self.add_node(derived_config)

        # We need an edge from the mitigation to the new config
        if not self.graph.has_edge(mitigation, derived_config):
            self.graph.add_edge(mitigation, derived_config)

        # And an edge from the parent config to the new config
        if not self.graph.has_edge(parent_config, derived_config):
            self.graph.add_edge(parent_config, derived_config)

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

        colors = [node_colors.get(self.graph.nodes[node]['type'], 'lightgray') for node in self.graph.nodes]
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

    def find_unexplored_configurations(self):
        """
        Find all configurations that have not been run yet.

        Returns:
            list: A list of configuration IDs that have not been linked to any failures or mitigations.
        """
        unexplored = [node for node, attrs in self.graph.nodes(data=True) 
                    if attrs['type'] == 'configuration' and \
                         not self.graph.nodes[node].get('run', False) ]
        return unexplored

class ConfigurationManager:
    def __init__(self, base_config):
        self.graph = ConfigurationGraph(base_config)

    def find_configs_from_failure_mitigation(self, failure_id, mitigation_id):
        '''
        Given a failure and a mitigation, find any new configurations that could be derived from them.
        Returns tuples of (derived_from, config_id)
        '''
        # STUB
        if failure_id == 'failure_A':
            if mitigation_id == 'mitigation_A0':
                return [("0", "A0")]
            elif mitigation_id == 'mitigation_A1':
                return [("0", "A1")]

        elif failure_id == 'failure_B':
            if mitigation_id == 'mitigation_B0':
                return [("0", "B0")]
            elif mitigation_id == 'mitigation_B1':
                return [("0", "B1"), ("A0", "C")]
        return []

    def find_mitigations_for(self, failure, config):
        '''
        Given a failure and a config, identify mitigations that could be applied.
        '''
        # STUB
        if failure == "A":
            return ["A0", "A1"]
        elif failure == "B":
            return ["B0", "B1"]
        elif failure == "C":
            return []
        else:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {failure}")

    def _run_config(self, config_id):
        '''
        Actually run a given config. SIMULATION for now
        Return a tuple of [failures], health_score
        '''
        # Make sure this config hasn't already been run
        assert(config_id in self.graph.find_unexplored_configurations())

        # Debug
        #self.graph.create_png("/results/config_graph.png")

        # STUB
        if config_id == "config_0":
            failures = ["A", "B"]
            health_score = 50

        elif config_id == "config_A0":
            # Successfully mitigated failure A. Yay
            # Slightly more healthy than base
            failures = ["B"]
            health_score = 60
        elif config_id == "config_A1":
            # Failed to mitigate A or B. Less healthy than base
            failures = ["A", "B"]
            health_score = 30

        elif config_id == "config_B0":
            # Successfully mitigated failure B. Yay
            failures = ["A"]
            health_score = 100
        elif config_id == "config_B1":
            # Mitigated A and B
            failures = ["B"]
            health_score = 30

        elif config_id == "config_C":
            failures = [] # Terminal node, no failures. Lots of health
            health_score = 3000
        else:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {config_id}")
        
        # Update graph to set run property
        self.graph.graph.nodes[config_id]['run'] = True

        return failures, health_score

    def run_configuration(self, config):
        """
        Run a given configuration to get a list of failure and a health score.
        Update the graph with the new information to set weights
        Add new failures and mitigations to the graph
        """

        failures, health_score = self._run_config(config)
        self.graph.report_config_run(config, health_score)

        # Now we add new failures that we observed during this run
        for failure in failures:
            self.graph.add_node(failure)
            self.graph.add_edge(config, failure)

            # Now for each of these failures, let's see if there are new mitigations
            # we could apply. We know the configuration that was run, and the failure.
            # Note the failure might not be new, but perhaps the mitigation is
            for mitigation in self.find_mitigations_for(failure, config):
                if not self.graph.graph.has_node(mitigation):
                    self.graph.add_node(mitigation)
                # Edge shoudl be new?? Maybe not
                self.graph.add_edge(failure, mitigation)

            # Now look at the mitigations for this failure, and see if there are any new configurations
            # we could derive from them.
            #self.find_configs_from_failure(failure)

            for mitigation in self.graph.mitigations_for(failure):
                for derived_from, config in self.find_configs_from_failure_mitigation(failure, mitigation):
                    # Add new config derived from this mitigation
                    self.graph.add_derived_configuration(config, derived_from, mitigation)

    def run_exploration_cycle(self):
        """ Get the best config and run it """
        if config_to_run := self.select_best_config():
            self.run_configuration(config_to_run)
            return True

        print("No more configurations to run.")
        return False

    def select_best_config(self):
        """ Select the best configuration to run next. Node can't have been run before """

        # Just return the first unexplored config for now
        # TODO: select based on weight and health score
        # we'd want to take config weights + mitigation weights into account
        # to identify an un-run config with the highest expected health score
        return self.graph.find_unexplored_configurations()[0]

def main():
    base_config = Configuration("config_0", {"some_data": "some_value"})
    config_manager = ConfigurationManager(base_config)

    # Run a series of exploration cycles
    for _ in range(15):  # Adjust the range as needed for testing
        if not config_manager.run_exploration_cycle():
            break

    # Visualize the resulting graph
    config_manager.graph.create_png("/results/config_graph.png")

if __name__ == "__main__":
    main()