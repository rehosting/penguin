import networkx as nx
import matplotlib.pyplot as plt
import pickle

class ConfigurationGraph:
    def __init__(self):
        """
        Initialize the graph.
        Creates an empty directed graph using NetworkX.
        """
        self.graph = nx.DiGraph()

    def add_configuration(self, config_id: str, parent_config: str = None):
        """
        Add a new configuration node to the graph.

        Args:
            config_id (str): Unique identifier for the new configuration.
            parent_config (str, optional): Identifier of the parent configuration. Defaults to None.
        """
        if not isinstance(config_id, str) or (parent_config is not None and not isinstance(parent_config, str)):
            raise ValueError("Invalid input types for add_configuration.")

        assert(config_id.startswith("config"))
        self.graph.add_node(config_id, type='configuration', run=False)

        if parent_config and self.graph.has_node(parent_config):
            self.graph.add_edge(parent_config, config_id, type='CC')
            
    def add_failure(self, config_id: str, failure_id: str):
        '''
        Add a new failure node to the graph, and link it to the specified configuration.
        '''
        if not self.graph.has_node(config_id):
            raise ValueError(f"Configuration {config_id} does not exist in the graph.")

        if not self.graph.has_node(failure_id):
            self.graph.add_node(failure_id, type='failure')
        self.graph.add_edge(config_id, failure_id, type='CF')

    def add_mitigation(self, mitigation_id: str, failure_id: str, initial_weight: float = 1.0):
        """
        Add a new mitigation node to the graph, with an initial weight for the edge.

        Args:
            mitigation_id (str): Unique identifier for the mitigation.
            failure_id (str): Identifier of the failure that this mitigation addresses.
            initial_weight (float, optional): Initial weight of the edge. Defaults to 1.0.
        """
        if not all(isinstance(arg, str) for arg in [mitigation_id, failure_id]):
            raise ValueError("Invalid input types for add_mitigation.")

        if not self.graph.has_node(failure_id):
            raise ValueError(f"Failure {failure_id} does not exist in the graph.")

        self.graph.add_node(mitigation_id, type='mitigation')
        self.graph.add_edge(failure_id, mitigation_id, type='FM', weight=initial_weight)

    def update_edge_weight(self, from_node: str, to_node: str, new_weight: float):
        """
        Update the weight of an edge in the graph.

        Args:
            from_node (str): The starting node of the edge.
            to_node (str): The ending node of the edge.
            new_weight (float): The new weight to assign to the edge.
        """
        if self.graph.has_edge(from_node, to_node):
            self.graph[from_node][to_node]['weight'] = new_weight
        else:
            raise ValueError("Edge does not exist in the graph.")

    def add_derived_configuration(self, derived_config_id: str, parent_config: str, mitigation_id: str):
        """
        Add a new configuration derived from a specific mitigation and parent configuration.

        Args:
            derived_config_id (str): Identifier for the derived configuration.
            parent_config (str): Identifier of the parent configuration.
            mitigation_id (str): Identifier of the mitigation leading to the derived configuration.
        """
        # ... existing validation code ...

        if not self.graph.has_node(mitigation_id):
            raise ValueError(f"Mitigation {mitigation_id} does not exist in the graph.")

        self.add_configuration(derived_config_id, parent_config=parent_config)
        self.graph.add_edge(mitigation_id, derived_config_id, type='MC')

    def prune_graph(self):
        """
        Prune the graph to remove redundant or fully explored nodes.

        This function removes nodes and edges that are deemed unnecessary for future exploration,
        based on certain criteria like node redundancy or lack of failure links.
        """
        # This is a placeholder for the pruning logic
        pass

    def get_next_config(self) -> str:
        """
        Determine the next configuration to run based on certain criteria.

        Returns:
            str: Identifier of the next configuration to run.

        This function selects the next configuration to run, based on criteria such as least explored,
        most promising based on failure mitigation, etc.
        """
        # This is a placeholder for the selection logic
        return ""

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

    def archive_node(self, node_id: str):
        """
        Archive a node before pruning.

        Args:
            node_id (str): Identifier of the node to be archived.

        This function archives the specified node's data before it's pruned from the graph.
        """
        # This is a placeholder for the archiving logic
        pass

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
                         not self.graph.nodes[node].get('run') ]
        return unexplored

    def generate_failure_mitigation_report(self):
        """
        Generate a report of all failures and their associated mitigations.

        Returns:
            dict: A dictionary where keys are failure IDs and values are lists of associated mitigation IDs.
        """
        report = {}
        for node, attrs in self.graph.nodes(data=True):
            if attrs['type'] == 'failure':
                mitigations = list(self.graph.successors(node))
                report[node] = mitigations
        return report
    
    def find_configs_from_mitigation(self, mitigation_id):
        """
        Find all configurations derived from a specific mitigation.

        Args:
            mitigation_id (str): The mitigation identifier.

        Returns:
            list: A list of configuration IDs derived from the specified mitigation.
        """
        configs = [node for node in self.graph.successors(mitigation_id) 
                if self.graph.nodes[node]['type'] == 'configuration']
        return configs

class ConfigurationManager:
    def __init__(self, base_config):
        self.graph = ConfigurationGraph()
        self.configurations = {}
        self.mitigations = {}  # Stores mitigation details
        self.failures = {}  # Stores failures details
        self.health_scores = {}  # Stores health scores for each configuration

        # Initialize with a base configuration
        self.add_configuration(base_config)

    def name(self, item, prefix='config'):
        """ Generate a unique name for a configuration or failure. """
        if item.startswith(prefix):
            print("WARNING: item already has prefix:", item)
            return item
        return f"{prefix}_" + (item if isinstance(item, str) else id(item))

    def add_configuration(self, config):
        """ Add a new configuration. """
        i = self.name(config)
        self.configurations[i] = config
        self.graph.add_configuration(i)

    def add_failure(self, failure, src):
        """ Add a new failure to the manager. """
        i = self.name(failure, 'failure')
        self.failures[i] = failure
        self.graph.add_failure(src, i)

    def add_mitigation(self, mitigation, src):
        """ Add a new mitigation to the manager. """
        i = self.name(mitigation, 'mitigation')
        self.mitigations[i] = mitigation
        self.graph.add_mitigation(i, src)

    def _run_config(self, config_id):
        '''
        Actually run a given config. SIMULATION for now
        Return a tuple of [failures], health_score
        '''
        # Make sure this config hasn't already been run
        assert(config_id in self.graph.find_unexplored_configurations())

        if config_id == "config_0":
            failures = ["A", "B"]
            health_score = 50

        elif config_id == "config_A0":
            failures = ["B"]
            health_score = 60
        elif config_id == "config_A1":
            failures = ["B"]
            health_score = 55

        elif config_id == "config_B0":
            failures = ["A"]
            health_score = 60
        elif config_id == "config_B1":
            failures = ["C"]
            health_score = 70

        elif config_id == "config_C":
            failures = []
            health_score = 70
            # C has no failures, but it's terminal. Hmm.
        else:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {config_id}")

        # Update graph to set run property
        self.graph.graph.nodes[config_id]['run'] = True

        return failures, health_score

    def run_configuration(self, config_id):
        """ Simulate the running of a configuration. Get a score. Identify failures. """

        failures, health_score = self._run_config(config_id)
        
        self.health_scores[config_id] = health_score # Shouldn't already exist?
        
        # Add each failure to the graph and link it to the configuration
        for failure in failures:
            self.add_failure(failure, config_id)

            # Now for each of these failures, let's see if there are new mitigations
            # we could apply. We know the configuration that was run, and the failure.

            for mitigation in self.find_mitigations_for(failure, config_id):
                # Add mitigation (if it doesn't already exist)
                self.add_mitigation(mitigation, 'failure_'+failure)

            # Now look at the mitigations for this failure, and see if there are any new configurations
            # we could derive from them.
            self.find_configs_from_failure(self.name(failure, 'failure'))

    def find_configs_from_failure(self, failure_id):
        # First get the failure node, then find all the mitigations from it

        # Given a failure in the graph, grab all its mitigations
        for mitigation in self.graph.graph.successors(failure_id):
            # For each, check if we now have any new configurations
            for derived_from, config_id in self.find_configs_from_failure_mitigation(failure_id, mitigation):
                if config_id not in self.configurations:
                    self.add_configuration(config_id)

                # Link the new configuration to the mitigation
                self.graph.add_derived_configuration(self.name(config_id), derived_from, mitigation)

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
                return [("0", "C")]
        return []

    def find_mitigations_for(self, failure, config):
        '''
        Given a failure and a config, identify mitigations that could be applied.
        '''
        if failure == "A":
            # For failure A we mitigate with mitigation A0. For now we ignore config
            return ["A0", "A1"]
        elif failure == "B":
            return ["B0", "B1"]
        elif failure == "C":
            return []
        else:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {failure}")

    def run_exploration_cycle(self):
        """ Run a cycle of exploring configurations. """
        config_to_run = self.select_best_config()
        if config_to_run:
            self.run_configuration(config_to_run)
            return True
        else:
            print("No more configurations to run.")
            return False

    def select_best_config(self):
        """ Select the best configuration to run next. Node can't have been run before """
        # Special case for the first configuration, it's the best

        unexplored_configs = self.graph.find_unexplored_configurations()
        #return max(self.health_scores, key=self.health_scores.get, default=None)
        # For each unexplored config, find the health score in self.health_scores
        # Return the one with the highest score
        best_config = None
        best_score = -1 
        for config in unexplored_configs:
            score = self.health_scores.get(config, 0)
            if score > best_score:
                best_score = score
                best_config = config
        return best_config

def main():
    config_manager = ConfigurationManager("0")

    # Run a series of exploration cycles
    for _ in range(15):  # Adjust the range as needed for testing
        if not config_manager.run_exploration_cycle():
            break

    # Visualize the resulting graph
    config_manager.graph.create_png("/results/config_graph.png")

if __name__ == "__main__":
    main()