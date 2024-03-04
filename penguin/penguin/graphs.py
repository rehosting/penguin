import networkx as nx
import pickle
from typing import Optional, List, Callable, Tuple, Dict, Set
from uuid import uuid4, UUID
from threading import Lock, RLock
from time import sleep
from pyvis.network import Network


def get_global_mitigation_weight(mitigation_type : str) -> float:
    '''
    Global hyperparameter for how much we should prioritize a given mitigation type.
    Intuition is that we should check all inits.

    With new approach of searching across a generation, we'll always
    cover the whole init generation. So now we can leave these all equal?

    TODO: it seems like pseudofiles are generally more important
    than env variables or blocking signals. Perhaps our search should be more of a:

    If any untested pseudofile failure mitigations - select
    If any untested env failure mitigations - select (dynval, then apply)
    If any untested signal failure mitigations - select

    Then select highest estimated scores of remaining un-run nodes.

    This would ensure we create devices (straightforward and often good),
    before we go into expensive dynval tests that infrequently work
    '''
    try:
        return {
            'init': 1,
            'pseudofiles': 1,
            'env': 1,
        }[mitigation_type]
    except KeyError:
        return 1

class GraphNode:
    '''
    Base class for all graph nodes
    '''
    def __init__(self, name):
        self.gid = uuid4() # Globally unique ID
        self.friendly_name = name # User friendly name. Can have duplicates
        self.info = {}

    def __repr__(self):
        # stringify type (since it will be a subclass)
        return f"{self.__class__.__name__}({self.friendly_name})"

    def __eq__(self, other):
        return (isinstance(other, GraphNode) and
            self.friendly_name == other.friendly_name and
            self.__class__ == other.__class__ and
            self.info == other.info)

    def __hash__(self):
        return hash(self._convert_to_hashable(self.info))

    def _convert_to_hashable(self, item, cache=None):
        if cache is None:
            cache = set()

        item_id = id(item)  # Unique identifier for the object based on its memory address

        if item_id in cache:
            # This item has already been visited, return a placeholder or the original item to avoid infinite recursion
            return f"<cyclic {item_id}>"

        cache.add(item_id)

        if isinstance(item, dict):
            return frozenset((key, self._convert_to_hashable(value, cache)) for key, value in item.items())
        elif isinstance(item, list):
            return tuple(self._convert_to_hashable(elem, cache) for elem in item)
        elif isinstance(item, set):
            return frozenset(self._convert_to_hashable(elem, cache) for elem in item)
        elif any(isinstance(item, t) for t in (int, float, str)):
            # For immutable types like ints, strings, tuples
            return item
        else:
            raise ValueError(f"Can't convert {item} to hashable")

    def to_dict(self):
        return {
            'node': self.__class__.__name__,
            'name': self.friendly_name,
            'info': self.info,
            'gid': str(self.gid),
        }

class Configuration(GraphNode):
    def __init__(self, name, info = None, exclusive = None):
        '''
        A configuration is a key value store of various properties.
        These are the inputs to our target system.
        A configuration will be marked as run=True once we've run it.

        Exclusive is a special flag to mark a one-off "exclusive" config
        that we'll run to learn about the parent failure.
        For example, if we have a pseudofile ioctl failure (A), we can mitigate with a symex mitigation (B)
        that creates a Configuration(exclusive=pseudofiles) (C). We'll run this exclusive config,
        only query the pseudofile plugin for mitigations, then apply these along side the symex mitigation (B)
        under the failure (A).

        No config may be drived from an exclusive config.
        '''
        super().__init__(name)
        self.run = False
        self.run_idx = None
        self.weight = 1.0 # Weight from parent config to this one XXX unused?
        self.health_score = 0
        self.info = info or {}
        self.exclusive = exclusive
        self.dependencies = set() # Set of configs that must be run before this one


class Failure(GraphNode):
    def __init__(self, name, type, info = None):
        '''
        Failures are observed by running our target system with a given
        config. These are of various types and have a dictionary of info

        The type and info are returned by analysis helpers that examine
        the results of running a config
        '''
        super().__init__(name)
        self.type = type
        self.info = info or {}

    def to_dict(self):
        super_dict = super().to_dict()
        super_dict['type'] = self.type
        return super_dict

class Mitigation(GraphNode):
    def __init__(self, name, type, info = None, exclusive=False):
        '''
        A mitigation is designed to mitigate an identified failure.
        It has a strategy that can be applied to a configuration that
        tries to mitigate the failure.

        The type/info is passed to a helper function to implement
        the mitigation for a given configuration.
        '''
        super().__init__(name)
        self.type = type
        self.info = info if info else {}
        self.exclusive = exclusive


class ConfigurationGraph:
    def __init__(self, base_config: Configuration):
        self.lock = RLock()
        self.graph = nx.DiGraph()
        if base_config:
            self.add_node(base_config)

    def add_node(self, node: GraphNode):
        if not isinstance(node, GraphNode):
            raise TypeError(f"node must be an instance of GraphNode or its subclasses. got {node}")

        with self.lock:
            if existing := self.get_existing_node(node):
                raise ValueError(f"Refusing to replace {existing} with {node} as they're equal")

            if self.graph.has_node(node.gid):
                raise ValueError(f"Node with id {node.gid} already exists")

            self.graph.add_node(node.gid, object=node)

    def has_node(self, node: GraphNode):
        with self.lock:
            return self.graph.has_node(node.gid)

    def has_edge(self, from_node: GraphNode, to_node: GraphNode):
        with self.lock:
            return self.graph.has_edge(from_node.gid, to_node.gid)

    def add_edge(self, from_node: GraphNode, to_node: GraphNode, weight : float = 1.0, unknown : bool = False, delta : str = None):
        with self.lock:
            edge_type = self.determine_edge_type(from_node, to_node)
            if not edge_type:
                raise ValueError(f"Invalid edge type between {from_node} and {to_node}")

            attrs = {
                'weight': weight,
                'unknown': unknown,
            }

            if edge_type == 'CC':
                # Only CC edges have a delta property
                attrs['delta'] = delta

            self.graph.add_edge(from_node.gid, to_node.gid, type=edge_type, **attrs)

    @staticmethod
    def determine_edge_type(from_node: GraphNode, to_node: GraphNode):
        edge_type_mapping = {
            (Configuration, Configuration): 'CC',
            (Configuration, Failure): 'CF',
            (Failure,       Mitigation): 'FM',
            (Mitigation,    Configuration): 'MC'
        }
        try:
            return edge_type_mapping[(type(from_node), type(to_node))]
        except KeyError:
            raise ValueError(f"Invalid edge type between {from_node} and {to_node}")

    def node_has_predecessor(self, node: GraphNode):
        '''
        Check if a given node has a predecessor
        '''
        with self.lock:
            return len(self.graph.pred[node.gid]) > 0

    def get_parent_config(self, config: Configuration) -> Optional[Configuration]:
        '''
        Given a config, find its parent config. Returns None if it's the root config
        '''
        with self.lock:
            if not self.node_has_predecessor(config):
                return None # Root

            for pred in self.graph.predecessors(config.gid):
                if isinstance(self.graph.nodes[pred]['object'], Configuration):
                    return self.graph.nodes[pred]['object']
            raise ValueError(f"Could not find parent config for {config}")

    def get_child_configs(self, config: Configuration) -> List[Configuration]:
        with self.lock:
            return [self.graph.nodes[n]['object'] for n in self.graph.successors(config.gid) \
                        if isinstance(self.graph.nodes[n]['object'], Configuration)]

    def get_parent_failure(self, config: Configuration) -> Optional[Failure]:
        '''
        Given a config, find its parent failure. Returns None if it's the root config
        '''
        with self.lock:
            if not self.node_has_predecessor(config):
                return None # Root

            mitigation = self.get_parent_mitigation(config)
            for failure_pred in self.graph.predecessors(mitigation.gid):
                if isinstance(self.graph.nodes[failure_pred]['object'], Failure):
                    return self.graph.nodes[failure_pred]['object']
            raise ValueError(f"Could not find parent config for {config}")

    def get_parent_mitigation(self, config: Configuration) -> Optional[Mitigation]:
        '''
        Given a config, find its parent mitigation. Returns None if it's the root config
        '''
        with self.lock:
            if not next(self.graph.predecessors(config.gid), None):
                return None # Root

            for pred in self.graph.predecessors(config.gid):
                if isinstance(self.graph.nodes[pred]['object'], Mitigation):
                    return self.graph.nodes[pred]['object']
            raise ValueError(f"Could not find parent mitigation for {config}")

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
        with self.lock:
            self.graph.nodes[config.gid]['object'].run = True
            if config.exclusive:
                # Exclusive nodes are good to run if we've never run them before.
                # Otherwise they're kind of bad? Not sure how to weight this, so for now
                # we'll say they have parent + 100 if we've never run them before, and
                # score of 0 otherwise.

                # Parent mitigation will have one out edge to this config if we've never run it before
                parent_mitigation = self.get_parent_mitigation(config)

                if config.run:
                    # We already ran this - ignore it (maybe redundant?)
                    health_score = 0
                elif len(self.graph[parent_mitigation.gid]) == 1:
                    # First time
                    health_score = self.get_parent_config(config).health_score + 100
                else:
                    # We've done this before. Bail
                    health_score = 0

            config.health_score = health_score

            parent_cc = self.get_parent_config(config)
            if parent_cc is None:
                return # Must be the root config!
            self.set_cc_edge_weight(parent_cc, config, health_score)

            # Add the weight to weights list in the parent fail -> parent mitigation node
            self.update_parent_fail_mit_weight(config, health_score)

    def add_dependencies(self, parent_config : Configuration, child_config : Configuration):
        # When we add a new child_config derived from a parent_config, we need to add deps
        # We have: grandparent_config -> parent_failure -> mitigation          -> parent config -> failure -> mitigation -> child_config
        #                                              \-> sibling_mitigation -> uncle config

        # But only if the parent_failure->sibling_mitigation edge has no weight - since then we don't know about it
        #self.graph[parent_fail.gid][parent_mit.gid]['weight'] = sum(weights) / len(weights)

        parent_fail = self.get_parent_failure(parent_config)
        grandparent_config = self.get_parent_config(parent_config)

        if not grandparent_config:
            # These must be the init nodes under the baseline - no dependencies
            return

        with self.lock:
            # We want to identify all the un-run configs that are siblings of the parent_config
            # meaning they share the parent of parent_config + parent_fail. They shouldn't have been run yet.
            assert (grandparent_config.gid in self.graph.nodes), f"Grandparent {grandparent_config} not in graph"

            uncles = [self.graph.nodes[n]['object'] for n in self.graph.successors(grandparent_config.gid) \
                        if isinstance(self.graph.nodes[n]['object'], Configuration) \
                            and self.graph.nodes[n]['object'] != parent_config \
                            and self.get_parent_failure(self.graph.nodes[n]['object']) == parent_fail \
                            and self.graph.nodes[n]['object'].run == False \
                            and len(self.graph[parent_fail.gid][self.get_parent_mitigation(self.graph.nodes[n]['object']).gid].get('weights',[])) == 0]

            # Now for each of the child configs of config, we'll add siblings as dependencies
            for dep in uncles:
                child_config.dependencies.add(dep)

    def update_parent_fail_mit_weight(self, config : Configuration, health_score :float):
        with self.lock:
            parent_fail = self.get_parent_failure(config)
            if parent_fail is None:
                return # error?

            parent_mit = self.get_parent_mitigation(config)

            # Get the edge from parent fail -> parent mit
            edge_type = self.determine_edge_type(parent_fail, parent_mit)
            if edge_type != 'FM':
                raise ValueError(f"Edge between {parent_fail} and {parent_mit} is of type {edge_type}, not FM")

            # Clear 'unknown' flag because weight is now concretely known
            self.graph[parent_fail.gid][parent_mit.gid]['unknown'] = False

            # Ensure we have a weights property as a list
            if 'weights' not in self.graph[parent_fail.gid][parent_mit.gid]:
                self.graph[parent_fail.gid][parent_mit.gid]['weights'] = []

            # How much did health increase from parent fail to this config?
            parent_config = self.get_parent_config(config)
            health_delta = health_score - parent_config.health_score

            # Add weight
            weights = self.graph[parent_fail.gid][parent_mit.gid]['weights']
            weights.append(health_delta)

            # Set average in 'weight'
            self.graph[parent_fail.gid][parent_mit.gid]['weight'] = sum(weights) / len(weights)

    def set_cc_edge_weight(self, from_node: Configuration, to_node: Configuration, new_weight: float):
        """
        Set the weight of an edge between two configurations in the graph.

        Args:
            from_node (str): The starting node of the edge.
            to_node (str): The ending node of the edge.
            new_weight (float): The new weight to assign to the edge.
        """
        with self.lock:
            if not self.graph.has_edge(from_node.gid, to_node.gid):
                raise ValueError("Edge does not exist in the graph.")

            # Make sure edge is of type CC
            edge_type = self.determine_edge_type(from_node, to_node)
            if edge_type != 'CC':
                raise ValueError(f"Edge between {from_node} and {to_node} is of type {edge_type}, not CC")

            # Make sure there wasn't a prior weight (1.0 is allowed sicne it's our default? This is just a sanity check for debugging)
            if 'weight' in self.graph[from_node.gid][to_node.gid] and self.graph[from_node.gid][to_node.gid]['weight'] != 1.0:
                raise ValueError(f"CC edge between {from_node} and {to_node} already has weight {self.graph[from_node][to_node]['weight']}")

            # Finally update the weight
            self.graph[from_node.gid][to_node.gid]['weight'] = new_weight

    def mitigations_for(self, failure):
        '''
        Given a failure, return a list of mitigations that could be applied
        '''
        with self.lock:
            return [self.graph.nodes[n]['object'] for n in self.graph.successors(failure.gid) \
                        if isinstance(self.graph.nodes[n]['object'], Mitigation)]

    @staticmethod
    def find_delta(derived, parent, prefix=""):
        '''
        Given two dicts, create a string representation of the difference between them.
        '''
        delta = ""
        all_keys = set(derived.keys()) | set(parent.keys())  # Union of keys in both dicts

        for key in all_keys:
            derived_value = derived.get(key, None)
            parent_value = parent.get(key, None)

            if isinstance(derived_value, dict) or isinstance(parent_value, dict):
                # If only one value is a dict, treat as a complete change.
                if not (isinstance(derived_value, dict) and isinstance(parent_value, dict)):
                    delta += f"{prefix}{key}: {parent_value if isinstance(parent_value, dict) else 'N/A'} -> {derived_value}\n"
                else:
                    # Both are dicts, recurse.
                    sub_delta = ConfigurationGraph.find_delta(derived_value, parent_value, prefix=f"{prefix}{key}.")
                    if sub_delta:
                        delta += sub_delta
            else:
                if derived_value != parent_value:
                    delta += f"{prefix}{key}: {parent_value} -> {derived_value}\n"

        # After refactoring to correctly identify differences, ensure this check reflects actual undetected changes.
        if delta == "" and derived != parent:
            print("WARNING: delta is empty but derived != parent")
            print("Derived:", derived)
            print("Parent:", parent)

        return delta.strip()


    def add_derived_configuration(self, derived_config: GraphNode, parent_config: GraphNode, mitigation: GraphNode):
        """
        Add a new configuration derived from a specific mitigation and parent configuration.
        """

        # Identify difference between derived_config and parent_config. In both nodes the .info
        # field is a dictionary of key/value pairs. We should only see a small difference,
        # a key may be added with some value, or a key may be changed.
        # We'll find this and store it as a string.
        # The challenge here is we need to recurse into the dictionaries to find the difference.
        delta = self.find_delta(derived_config.info, parent_config.info)

        if derived_config == parent_config:
            print(f"WARNING: derived_config == parent_config: {derived_config} == {parent_config}")
            print(f"\tDelta is: {delta}")
            print("\tIgnoring")
            return

        with self.lock:
            if not self.graph.has_node(mitigation.gid):
                raise ValueError(f"Mitigation {mitigation} does not exist in the graph.")

            if not self.graph.has_node(parent_config.gid):
                raise ValueError(f"Parent configuration {parent_config} does not exist in the graph.")

            # derived_config is our new config - this is probably new
            if not self.graph.has_node(derived_config.gid):
                #print(f"Adding new derived config: {derived_config}")
                self.add_node(derived_config)
            else:
                # Assert parent config is a configuration that has been run
                if not isinstance(self.graph.nodes[parent_config.gid]['object'], Configuration):
                    raise TypeError(f"Config can't be drived from {parent_config}: that is not a configuration")
                if not self.graph.nodes[parent_config.gid]['object'].run:
                    raise ValueError(f"Can't derive config from un-run {parent_config}")

            # We need an edge from the mitigation to the new config
            if not self.graph.has_edge(mitigation.gid, derived_config.gid):
                self.add_edge(mitigation, derived_config)

            # And an edge from the parent config to the new config
            if not self.graph.has_edge(parent_config.gid, derived_config.gid):
                self.add_edge(parent_config, derived_config, delta=delta)

        if parent_config.exclusive is not None:
            raise ValueError(f"Cannot derive config from an exclusive config: {parent_config}")

        # Mark the derived config as coming from this parent and blocking until the parents siblings are explored
        self.add_dependencies(parent_config, derived_config)

    def save_graph(self, file_path: str):
        """
        Save the graph to a file using pickle.

        Args:
            file_path (str): The file path where the graph should be saved.
        """
        if not isinstance(file_path, str):
            raise ValueError("Invalid input type for file_path.")

        with open(file_path, 'wb') as f:
            with self.lock:
                pickle.dump(self.graph, f)

    # Colors based on node type (configuration, failure, mitigation) or edge type (CF, FC, CC)
    @staticmethod
    def _node_color(obj : GraphNode):

        # Non-config nodes are colored by type
        node_colors = {
            Failure: 'lightcoral',
            Mitigation: 'lightyellow',
        }

        # Config nodes are colored by properties
        config_colors = {
            # (run, exclusive): color
            (False, False): 'lightgray', # Non-exclusive + pending
            (False, True): 'gray',       # Exclusive     + pending
            (True, False): 'lightblue',  # Non-exclusive + run
            (True, True): 'black',       # Exclusive     + run
        }

        if isinstance(obj, Configuration):
            # Configurations have variable colors depending on exclusive and run flags
            color = config_colors[(obj.run, obj.exclusive is not None)]
        else:
            color = node_colors[type(obj)]
        return color


    def create_html(self, file_path: str):
        """
        Create an interactive html page of the graph

        Args:
            file_path (str): The file path where the HTML image will be saved.
        """
        if not isinstance(file_path, str):
            raise ValueError("Invalid input type for file_path.")

        # We need to make a new graph with the same nodes and edges, but with
        # the friendly names as the node labels. We'll also add a title attribute
        # with the details so it gets pretty printed
        new_graph = nx.DiGraph()

        # Helper function to generate HTML for node titles
        def generate_html_title(node_obj):
            html_parts = [f"<b>{node_obj.__class__.__name__}</b>: {node_obj.friendly_name}"]
            if isinstance(node_obj, Configuration):
                if node_obj.run:
                    html_parts.extend([
                        f"Run idx: {node_obj.run_idx}",
                        f"Weight: {node_obj.weight}",
                        f"Health Score: {node_obj.health_score}",
                        f"Exclusive: {node_obj.exclusive}",
                        #f"Info: {node_obj.info}"
                    ])
                else:
                    html_parts.extend([
                        f"Exclusive: {node_obj.exclusive}",
                    ])
            elif isinstance(node_obj, Failure):
                html_parts.extend([
                    f"Type: {node_obj.type}",
                    #f"Info: {node_obj.info}"
                ])
            elif isinstance(node_obj, Mitigation):
                html_parts.extend([
                    f"Type: {node_obj.type}",
                    #f"Info: {node_obj.info}"
                ])

            return ", ".join(html_parts)

        # Add nodes with string identifiers and customized attributes
        with self.lock:
            for node in self.graph.nodes:
                node_obj = self.graph.nodes[node]['object']
                if not isinstance(node_obj, Configuration):
                    continue

                node_id = str(node_obj.gid)
                node_color = self._node_color(self.graph.nodes[node]['object'])
                node_title = generate_html_title(node_obj)

                #label = node_obj.friendly_name
                label = f"{str(node_obj.health_score)+' ' if isinstance(node_obj, Configuration) else ' '}{node_obj.friendly_name}"
                # Level is the number of predecessors from the root
                level = 0
                for _ in nx.ancestors(self.graph, node):
                    level += 1

                new_graph.add_node(node_id,
                                label=label,
                                level=level,
                                color=node_color)
                new_graph.nodes[node_id]['title'] = node_title

            # Add edges with mapped node identifiers
            for u, v, d in self.graph.edges(data=True):
                if d['type'] != 'CC':
                    continue
                u_id = str(self.graph.nodes[u]['object'].gid)
                v_id = str(self.graph.nodes[v]['object'].gid)
                new_graph.add_edge(u_id, v_id, type=d['type'])

        #nt = Network('800px', directed=True, layout='hierarchical', cdn_resources='remote')
        nt = Network('800px', directed=True, cdn_resources='remote')
        #nt.show_buttons(filter_=['physics'])  # This will enable a physics configuration menu in the rendered graph
        nt.show_buttons()
        nt.from_nx(new_graph)
        nt.save_graph(file_path)

    def create_config_png(self, file_path: str):
        raise NotImplementedError
        import matplotlib.pyplot as plt
        """
        Create a PNG image of the graph with just configurations and edges between them.
        We must show the delta property on the edges.
        """

        if not isinstance(file_path, str):
            raise ValueError("Invalid input type for file_path.")

        # Create a subgraph with only Configuration nodes and CC edges
        with self.lock:
            # Filtering edges that are of type 'CC'
            config_edges = [(u, v) for u, v, d in self.graph.edges(data=True) if d.get('type') == 'CC']

            # Create subgraph from these edges
            temp_graph = self.graph.edge_subgraph(config_edges)

            # Filtering nodes in this subgraph that are instances of Configuration
            config_nodes = [n for n in temp_graph.nodes if isinstance(temp_graph.nodes[n]['object'], Configuration)]

            # Creating the final subgraph with the filtered nodes
            this_graph = temp_graph.subgraph(config_nodes).copy()

        # Adjust figure size based on the number of nodes
        num_nodes = this_graph.number_of_nodes()
        figure_size = max(8, num_nodes / 3)  # Adjust the denominator for scaling
        plt.figure(figsize=(figure_size, figure_size))

        # Layout
        pos = nx.nx_agraph.graphviz_layout(this_graph, prog='dot', args='-Gnodesep=0.5 -Granksep=1 -Gmargin=0.5')
        #pos = nx.nx_agraph.graphviz_layout(this_graph, prog='neato', args='-Goverlap=scalexy -Gsep=+25')
        #pos = nx.spring_layout(this_graph)  # Alternative layout

        # Node labels mapping: gid -> friendly_name
        display_labels = {n: attr['object'].friendly_name for n, attr in this_graph.nodes(data=True)}

        # Draw nodes
        nx.draw(this_graph, pos, labels=display_labels, with_labels=True, node_color='lightblue',
                node_size=3500, font_size=6, arrowsize=20)

        # Draw edge labels showing 'delta'
        edge_labels = {(u, v): f"{d['delta']}" for u, v, d in this_graph.edges(data=True)}
        nx.draw_networkx_edge_labels(this_graph, pos, edge_labels=edge_labels, font_color='black')

        # Save to file
        plt.savefig(file_path)
        plt.close()

    def create_png(self, file_path: str):
        """
        Create a PNG image of the graph with enhanced visual features.

        Args:
            file_path (str): The file path where the PNG image will be saved.
        """
        raise NotImplementedError
        import matplotlib.pyplot as plt

        if not isinstance(file_path, str):
            raise ValueError("Invalid input type for file_path.")

        edge_colors = {"CF": "black", "FC": "black", "CC": "green"}
        edge_styles = {"CF": "dotted", "FC": "dotted", "CC": "solid"}

        # Create a subgraph with only Configuration nodes and CC edges
        with self.lock:
            # Create a copy of the graph excluding 'CC' edges between Configuration nodes
            this_graph = self.graph.copy()
            # Iterate over the edges and remove 'CC' edges as needed
            for u, v, data in list(this_graph.edges(data=True)):
                if data.get('type') == 'CC' and isinstance(this_graph.nodes[u]['object'], Configuration) and isinstance(this_graph.nodes[v]['object'], Configuration):
                    this_graph.remove_edge(u, v)

            colors = [self._node_color(this_graph.nodes[node]['object']) for node in this_graph.nodes]
            edge_colors = [edge_colors.get(this_graph.edges[edge]['type'], 'black') for edge in this_graph.edges]
            edge_styles = [edge_styles.get(this_graph.edges[edge]['type'], 'solid') for edge in this_graph.edges]

            # Calculate the figure size dynamically based on the number of nodes
            num_nodes = len(this_graph.nodes())
            figure_size = max(8, num_nodes / 3)  # Adjust the denominator for scaling

            # Set constraint=False for edges that are not of type 'CC' to guide dot
            #for u, v, d in this_graph.edges(data=True):
            #    if d.get('type') != 'CC':
            #        this_graph.edges[u, v]['constraint'] = False

            # Make all CC edges invisible
            #for u, v, d in this_graph.edges(data=True):
            #    if d.get('type') == 'CC':
            #        this_graph.edges[u, v]['style'] = False

            plt.figure(figsize=(figure_size, figure_size))

            # Use a layout algorithm to space out the nodes
            pos = nx.nx_agraph.graphviz_layout(this_graph, prog='dot')#, args='-Gnodesep=1 -Granksep=1 -Gmargin=1')
            #pos = nx.nx_agraph.graphviz_layout(this_graph, prog='neato', args='-Goverlap=scalexy -Gsep=+25')
            #pos = nx.spring_layout(this_graph)  # Alternative layout

            # We want to label each node with .friendly_name field, not .gid
            # To do this we'll create a mapping from gid -> id
            display_labels = {node: f"{this_graph.nodes[node]['object'].friendly_name}" + \
                                    (f" {this_graph.nodes[node]['object'].health_score or self.calculate_expected_config_health(this_graph.nodes[node]['object']):,}" \
                                     if isinstance(this_graph.nodes[node]['object'], Configuration) else "") \
                               for node in this_graph.nodes}

            nx.draw(this_graph, pos, labels=display_labels, with_labels=True, node_color=colors,
                    edge_color=edge_colors, style=edge_styles, node_size=2500, font_size=10, arrowsize=20)

            # Draw edge labels for FM edges
            #for u, v, d in this_graph.edges(data=True):
            #    print(f"Edge from {u} to {v} of type {d['type']}. Weight: {d.get('weight', 'NA')}")

            fm_edge_labels = {(u, v): f"{d['weight']:.02f}" for u, v, d in this_graph.edges(data=True) if d['type'] == 'FM'}
            nx.draw_networkx_edge_labels(this_graph, pos, edge_labels=fm_edge_labels, font_color='green')

        plt.savefig(file_path)
        plt.close()

    def find_unexplored_configurations(self, exclude : Set[Configuration] = None, potential : Optional[List[Configuration]] = None) -> List[Configuration]:
        """
        Find all configurations that have not been run yet.

        If exclude is provided, we'll exclude those configurations from the search.
        If parent is set, we'll only consider direct descendants of that parent.

        Returns:
            list: A list of configuration IDs that have not been linked to any failures or mitigations.
        """

        # Potential stores node name -> {'object': node object} for all potential nodes for us to consider
        with self.lock:
            # Get all nodes
            if potential is None:
                potential = [self.graph.nodes[node]['object'] for node, _ in self.graph.nodes(data=True)]

            # Now filter for un-run configs that aren't in our exclude list
            unexplored = [node for node in potential \
                            if isinstance(node, Configuration) \
                                and not node.run \
                                and not node in (exclude or []) ]
        return unexplored

    def get_best_run_configuration(self) -> Optional[Configuration]:
        '''
        Find the configuration with the highest health score - not estimated, actual.
        '''
        with self.lock:
            best = None
            for node in self.graph.nodes:
                if isinstance(self.graph.nodes[node]['object'], Configuration) and self.graph.nodes[node]['object'].run:
                    if best is None or self.graph.nodes[node]['object'].health_score > best.health_score:
                        best = self.graph.nodes[node]['object']
            return best.run_idx if best else None

    def get_all_configurations(self) -> List[Configuration]:
        '''
        Get all configurations in our graph
        '''
        with self.lock:
            return [self.graph.nodes[node]['object'] for node in self.graph.nodes \
                        if isinstance(self.graph.nodes[node]['object'], Configuration)]

    def get_root_config(self) -> Optional[Configuration]:
        with self.lock:
            # Search for the root config
            # This is the only config with no predecessors
            with self.lock:
                for node in self.graph.nodes:
                    if not any([isinstance(self.graph.nodes[pred]['object'], Configuration) for pred in self.graph.predecessors(node)]):
                        return self.graph.nodes[node]['object']
        return None



    def get_node(self, node_id: UUID) -> GraphNode:
        """
        Get a node from the graph.

        Args:
            node_id (str): The ID of the node to retrieve.

        Returns:
            GraphNode: The node with the given ID.
        """
        with self.lock:
            if not isinstance(node_id, UUID):
                raise ValueError(f"Invalid input type for node_id: {node_id}, {type(node_id)}")

            if not self.graph.has_node(node_id):
                raise ValueError(f"Node with ID {node_id} does not exist in the graph.")

            return self.graph.nodes[node_id]['object']

    def get_existing_node_or_self(self, new_node : GraphNode ) -> GraphNode:
        '''
        Given a new node, return the existing node in the graph if it exists.
        Otherwise return the new node. Check with hashing of node object
        '''
        with self.lock:
            for node in self.graph.nodes():
                if self.graph.nodes[node]['object'] == new_node:
                    # Found an existing node
                    return self.graph.nodes[node]['object']

            # No existing node
            return new_node

    def get_existing_node(self, new_node : GraphNode ) -> Optional[GraphNode]:
        with self.lock:
            for node in self.graph.nodes():
                if self.graph.nodes[node]['object'] == new_node:
                    # Found an existing node
                    return self.graph.nodes[node]['object']
            return None

    def _stringify_config(self, node, output, pending_runs, depth=0, visited=None):
        '''
        Add a report of parent to output. Recurse to children
        with depth + 1 and do so in order.
        '''
        if visited is None:
            visited = set()

        # Prevent processing a node more than once
        if node.gid in visited:
            return
        visited.add(node.gid)

        pad = " " * depth

        delta = 'N/A'
        if parent := self.get_parent_config(node):
            # Get edge from parent -> node and lookup delta
            delta = self.graph[parent.gid][node.gid].get('delta', 'N/A')

        oneline_delta = ", ".join(delta.splitlines())

        if node.run_idx is not None:
            s = f"{pad}{node.run_idx}: score = {node.health_score:_}. delta = {oneline_delta}"
        elif node in pending_runs:
            s = f"{pad}running: estimated score = {self.calculate_expected_config_health(node):_}. delta = {oneline_delta}"
        else:
            s = f"{pad}unexplored: estimated score = {self.calculate_expected_config_health(node):_}. delta = {oneline_delta}"
        output.append(pad + s)

        # Now we recurse to children, but we must sort them by score!
        with self.lock:
            children = [self.graph.nodes[x]['object'] for x in self.graph.successors(node.gid) if isinstance(self.graph.nodes[x]['object'], Configuration)]
        # We sort based on concrete healt score (node.health_score) if available, otherwise self.calculate_expected_config_health
        children = sorted(children, key=lambda x: x.health_score \
                            if x.health_score \
                            else self.calculate_expected_config_health(x),
                          reverse=True)

        for child in children:
            if child == node:
                continue # Skip if we encounter a self-loop
            self._stringify_config(child, output, pending_runs, depth + 1, visited)


    def calculate_expected_config_health(self, cc) -> float:
        '''
        Given a config, calculate the expected health score of that config.
        Note this ignores any actual health score we've seen for this config.
        '''
        parent_cc = self.get_parent_config(cc)
        if parent_cc is None:
            return cc.health_score # No parent failure to consider. Root node?

        # We'll calculate the expected weight as the sum of the parent config health
        # and parent mitigation

        # Get the weight between the parent failure and parent mitigation
        parent_fail = self.get_parent_failure(cc)
        parent_mit = self.get_parent_mitigation(cc)

        # Extract weight from edge. This is the average score delta we expect to see when
        # this mitigation is applied to this failure
        mitigation_weight = self.graph[parent_fail.gid][parent_mit.gid]['weight']

        expected = parent_cc.health_score + mitigation_weight + get_global_mitigation_weight(parent_mit.type)

        # A mitigation can specify its own weight as a constant that we'll add to our learned
        # weight. This lets a plugin rank the mitigations it produces
        if 'weight' in parent_mit.info:
            expected += parent_mit.info['weight']

        # If we saw a new failure in our parent config, that's a pretty good sign - we've uncovered
        # something new that we might want to mitigate. If this mitigation is hitting
        # such a failure, let's give this a big bonus!

        # If our parent_fail has a single in-edge, and it's from the parent config, then
        # it's bonus time!
        # The first time we see an SXID it's a mitigation
        # so we have

        # ONLY ONE CONFIG HAS THIS FAIULRE
        # config --> failure_missing_dsa -> *New mitigation = something*  -> New config with bonus

        # Check if parent failure has a single in-edge (from parent config)
        ''''
        with self.lock:
            parent_fail_parent_configs = [self.graph.nodes[n]['object'] for n in self.graph.predecessors(parent_fail.gid) \
                                        if isinstance(self.graph.nodes[n]['object'], Configuration)]
        new_fail_bonus = len(parent_fail_parent_configs) == 1
        '''

        '''
        # Look at the parent_mit's out edges - have any of them been run?
        # If so, we'll give a bonus to this config
        # Configs that descend from this mitigation
        with self.lock:
            mit_descendents = [self.graph.nodes[n]['object'] for n in self.graph.successors(parent_mit.gid) \
                                if isinstance(self.graph.nodes[n]['object'], Configuration)]
        new_fail_bonus = not any([cc.run for cc in mit_descendents])
        '''

        # If this config is mitigating a failure that the parent had BUT NOT THE GRANDPARENT
        # then it's kinda cool (i.e., parent fixes something, reveals new failure, now we try to fix)

        # First, do we have a grandparent?
        new_fail_bonus = True
        grandparent_cc = parent_cc
        while grandparent_cc := self.get_parent_config(grandparent_cc):
            # If there's an edge from this grand(^x)-parent to the failure, then it's not exciting
            if self.graph.has_edge(grandparent_cc.gid, parent_fail.gid):
                new_fail_bonus = False
                break

        if new_fail_bonus:
            # We like mitigating newly discovered! Give it a big bonus
            expected += 2000 # TODO: make this hyperparam more explicit?

        if cc.exclusive:
            # We like running these when we have the chance - bias towards them strongly!
            if not cc.run:
                expected += 1000 # TODO: make this hyperparam more explicit?

        return expected


class ConfigurationManager:
    def __init__(self, base_config : Configuration):
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
        self.lock = Lock() # Guards access to pending_runs and select_best_config
        self.pending_runs = set() # Set of configs we're currently running

    def stringify_state2(self):
        '''
        Return a string representation of the current graph.
        Each node should have a line. Under each node we'll indent and list out edges
        '''
        output = []
        with self.lock:
            for node in self.graph.graph.nodes:
                node_obj = self.graph.graph.nodes[node]['object']
                # We'll print the config, then the edges
                output.append(f"{node_obj}, {node_obj.gid}, {node_obj.info}")
                # For each adjacent node, print the node
                for neighbor in self.graph.graph.adj[node]:
                    weight = self.graph.graph[node][neighbor].get('weight', '')
                    output.append(f"\tEdge to: {self.graph.graph.nodes[neighbor]['object']}, {self.graph.graph.nodes[neighbor]['object'].gid} {weight}")

        return "\n".join(output)

    def stringify_state(self):
        '''
        Return a string representation of the current graph.

        Organize configs by run idx. Report deltas from parent
        Report score/pending/estimated for each config
        '''
        # First we'll loop through all configs and identify: parent, score, pending, estimated score

        # First we get root config
        root = self.graph.get_root_config()
        if not root:
            print(self.graph.graph)
            raise ValueError("No root config: cannot stringify")
        output = []
        self.graph._stringify_config(root, output, self.pending_runs)
        return "\n".join(output)


    def run_configuration(self, config : Configuration, weight : float,
                          run_config_f : Callable[[Configuration], Tuple[List[Failure], float]],
                          find_mitigations_f: Callable[[Failure, Configuration], List[Mitigation]],
                          find_new_configs_f: Callable[[Failure, Mitigation, Configuration],
                                                       List[Configuration]],
                          logger: Optional[Callable[[str], None]] = None):

        """
        Run a given configuration to get a list of failure and a health score.
        Update the graph with the new information to set weights
        Add new failures and mitigations to the graph
        """
        if logger is not None:
            logger.info(f"Running config {config} with weight {weight:,}")
        failures, health_score, run_idx = run_config_f(config)

        if run_idx is None:
            # We failed to run it
            logger.warning(f"Failed to run config {config}")
            return

        if logger is not None:
            logger.info(f"Finished run {run_idx} score {health_score:,} vs expected {weight:,} (delta {health_score-weight}): {config}")

        # Sets run, health(?), and updates weights
        config.run_idx = run_idx
        self.graph.report_config_run(config, health_score)

        target_config = config

        if config.exclusive:
            # Special case. We have an exclusive config. It should have yielded ONE failure (or none)
            if not len(failures):
                return # no -op
            #assert(len(failures) <= 1), f"Got multiple failures from exclusive config: {failures}"
            print(f"WARNING: Got multiple failures from exclusive config - only expected one. Config={config}, failiure={failures}")
            target_config = self.graph.get_parent_config(config)

        # Normal case: Now we add new failures that we observed during this run
        for orig_failure in failures:
            # Think of failure as "failure source" that we're trying to find mitigations for

            if config.exclusive:
                # In exclusive mode we don't add a new failure, we merge back to parent's failure instead.
                # This is a bit hairy. Keep an eye on orig_failure vs failure. orig_failure is always
                # the actual failure we observed, while failure is the parent failure IFF exclusive mode
                # otherwise it's the same as orig_failure.
                failure = self.graph.get_parent_failure(config)
            else:
                failure = orig_failure

                # Find failure in graph or add it
                if existing_node := self.graph.get_existing_node(failure):
                    failure = existing_node
                else:
                    self.graph.add_node(failure)

                # Add edge from source config -> failure
                self.graph.add_edge(config, failure)

            # Now for each of these failures, let's see if there are new mitigations
            # we could apply. We know the configuration that was run, and the failure.
            # Note the failure might not be new, but perhaps the mitigation is
            try:
                mitigations = find_mitigations_f(orig_failure, config)
            except Exception:
                raise ValueError(f"Error finding mitigations for {orig_failure} from {config}")

            for mitigation in mitigations:
                if logger is not None:
                    logger.debug(f"Trying to mitigate {failure} with {mitigation}")
                with self.lock:
                    if existing_mit := self.graph.get_existing_node(mitigation):
                        mitigation = existing_mit

                    if not self.graph.has_node(mitigation):
                        self.graph.add_node(mitigation)

                    # Edge from failure (perhaps parent failure) to this new mitigation
                    # If we learned something from an exclusive config (i.e., symex value, env val), it should be unknown,
                    # unless we've previously seen this mitigation before (in which case we might already have a weight)
                    if not self.graph.has_edge(failure, mitigation):
                        self.graph.add_edge(failure, mitigation, unknown=config.exclusive)

            # Now try finding mitigations. This might be for the parent failure if it was exclusive
            for mitigation in self.graph.mitigations_for(failure):
                if logger is not None:
                    logger.debug(f"A mitigation for {failure} is {mitigation}")
                for new_config in find_new_configs_f(failure, mitigation, target_config):
                    with self.lock:
                        if existing_config := self.graph.get_existing_node(new_config):
                            #if logger is not None:
                            #    logger.info(f"Not adding {new_config} because it already exists as {existing_config}")
                            new_config = existing_config
                        # If we were exclusive we pretend new config is derived from parent config
                        # (Because it kind of is)
                        self.graph.add_derived_configuration(new_config, target_config, mitigation)

    def run_exploration_cycle(self, run_config_f : Callable[[Configuration], Tuple[List[Failure], float]],
                            find_mitigations_f: Callable[[Failure, Configuration], List[Mitigation]],
                            find_new_configs_f: Callable[[Failure, Mitigation, Configuration],
                                                         List[Configuration]],
                            logger: Optional[Callable[[str], None]] = None):
        """
        Get the best config and run it. Hold lock while selecting.
        While we're running, ensure config is in self.pending_runs
        """

        with self.lock:
            config_to_run, weight = self.select_best_config()
            if config_to_run:
                self.pending_runs.add(config_to_run)

        if not config_to_run:
            # Sleep, without lock, since no configs were available. Then bail
            sleep(1)
            return

        self.run_configuration(config_to_run, weight, run_config_f, find_mitigations_f, find_new_configs_f, logger)

        with self.lock:
            self.pending_runs.remove(config_to_run)
        return config_to_run

    def select_best_config(self) -> Tuple[Optional[Configuration], float]:
        """
        First try finding an un-run+non-pending config that's derived from a mitigation
        we've never run before. Prioritize by expected health score.

        If we've run every mitigation, just select the best config based on expected health score.
        """
        # For every unexplored config, get parent mitigation and store mit -> (weight, config). When we have multiple
        # configs for a mit, clobber if we find a better weight

        # Select most shallow un-run config with best health score
        pending = {}
        unexplored_configs = self.graph.find_unexplored_configurations()
        for config in unexplored_configs:
            if config not in self.pending_runs:
                parent_mit = self.graph.get_parent_mitigation(config)

                if parent_mit is None:
                    continue

                # Have *any* of the child configs of parent_mit been run / are running? If so bail
                if any([self.graph.graph.nodes[child]['object'] in self.pending_runs or \
                        self.graph.graph.nodes[child]['object'].run \
                            for child in self.graph.graph.successors(parent_mit.gid) \
                                if isinstance(self.graph.graph.nodes[child]['object'], Configuration)]):
                    continue

                this_score = self.graph.calculate_expected_config_health(config)
                this_depth = -self.calculate_config_depth(config)
                if parent_mit not in pending or \
                        this_depth > pending[parent_mit][2] or \
                        (this_depth == pending[parent_mit][2]and this_score > pending[parent_mit][0]):
                    pending[parent_mit] = (this_score, config, this_depth)

        # Now we have a mapping of mit -> (weight, config) for every unexplored mitigation.
        target_configs = pending.values()

        if not len(target_configs):
            target_configs = []
            # There are no unexplored mitigations! Just select globally best config
            unexplored = self.graph.find_unexplored_configurations()
            for config in unexplored:
                if config not in self.pending_runs:
                    target_configs.append((self.graph.calculate_expected_config_health(config), config))

        if not len(target_configs):
            # Nothing to do. Other threads are working or we're all out of work
            return None, 0

        # Now we have a list of (health, config) tuples. Sort by health and return the best config + weight
        results = sorted(target_configs, key=lambda x: x[0], reverse=True)
        weight, best = results[0][:2]

        if best in self.pending_runs:
            raise ValueError(f"Selected {best} but it's already pending")

        if best.run:
            raise ValueError(f"Selected {best} but it's already run")

        # One more check. If best is far deeper in graph than a pending node, let's stall
        # this is to avoid issues where we descend too quickly - failures might fail fast and we might propose
        # many mitigations (using our whole run queue) before we've even finished running the first config

        # find lowest depth of all running nodes
        lowest_depth = min([self.calculate_config_depth(x) for x in self.pending_runs], default=self.calculate_config_depth(best))


        #if self.calculate_config_depth(best) - lowest_depth > 3:
        #    print(f"Stalling {best} with score {weight:,} because it's too deep in the graph ({self.calculate_config_depth(best)}) compared to running nodes ({lowest_depth})")
        #    return None, 0

        return best, weight


    def select_best_config_orig(self) -> Tuple[Optional[Configuration], float]:
        """
        Select the best configuration to run next. Node can't have been run before

        Just return the first unexplored config for now

        For each un-run node, we look at its parent config and parent mitigation.
        We can calculate an expected weight based on these two as:
        expected_weight = parent_config_weight + parent_mitigation_weight

        We support biasing this calculation when we get results that are better than expected from
        equally-likely-to-be-good mitigations. E.g., if we add two inits and just run one,
        we bias the health score of the other to be comprably weighed instead of falling behind
        and never getting run.

        We do this for inits, dynamically-discovered env vars, and ioctl models.

        XXX: We assume these nodes all show up at the same time - i.e., after an exclusive
        nodes runs. If that changes later, we'll need to better track these

        Call with self.lock held!
        """

        # Ensure self.lock is held
        assert(self.lock.locked()), f"select_best_config called without lock held"

        # If we have pending configs, we must select from them.
        unexplored = self.graph.find_unexplored_configurations(exclude=self.pending_runs)

        # We'd like to avoid selecting any exclusive configs if there's already an alternate version
        # of that config that's actively running.
        # We'll make a copy of unexplored, then remove these nodes
        # if we're empty at that point, we'll just go back to using the original unexplord set
        unexplored_copy = unexplored.copy()
        for cc in unexplored_copy:
            if cc.exclusive:
                # We have an exclusive config. Are any other versions of this mitigation currently running?
                parent_mit = self.graph.get_parent_mitigation(cc)
                # Now check if any of the child configs of this mitigation are in self.pending_runs
                for child in self.graph.graph.successors(parent_mit.gid):
                    if isinstance(self.graph.graph.nodes[child]['object'], Configuration) and \
                            self.graph.graph.nodes[child]['object'] in self.pending_runs:
                        unexplored_copy.remove(cc)
                        break

        if len(unexplored_copy):
            unexplored = unexplored_copy

        if len(unexplored) == 0:
            print(f"No configs available, {len(self.pending_runs)} pending runs: {self.pending_runs}")
            return None, 0

        weights = {} # config -> weight
        for cc in unexplored:
            weights[cc] = self.graph.calculate_expected_config_health(cc)

        if len(unexplored) == 0:
            return None, 0

        # Sort by weight and select the highest
        sorted_weights = sorted(weights.items(), key=lambda x: x[1], reverse=True)
        best = sorted_weights[0][0]


        # After we selected the node with the highest estimated weight, we'll do some extra analyses
        # to make sure we're on the right track. These are toggled below

        if True:
            # Check from depth 0..N to see if ANY un-executed config looks more promising than our predecessor at that depth
            parent_healths = []
            parent = self.graph.get_parent_config(best)
            while parent:
                parent_healths.append(parent.health_score)
                parent = self.graph.get_parent_config(parent)
            parent_healths = parent_healths[::-1] # Reverse so we start at depth 0
            # Now we look across entire graph for un-run+non-pending configs to see if any have a higher expected score
            # than our parent does at that depth.
            best_depths = {
                depth: value for depth, value in zip(range(len(parent_healths)), parent_healths)
            }

            current_depth = self.calculate_config_depth(best)
            #best_depths[self.calculate_config_depth(best)] = self.graph.calculate_expected_config_health(best)

            better_options = {
                # depth: config. Config is set/updated IFF value is better than that in best_depths[depth]
            }

            # For every node in the graph
            for cc in self.graph.get_all_configurations():
                if cc in self.pending_runs or cc.run:
                    continue
                this_depth = self.calculate_config_depth(cc)

                if this_depth >= current_depth:
                    # If a config is as deep or deeper than us, it can't be a better option earlier in our tree
                    continue


                this_health = self.graph.calculate_expected_config_health(cc)

                # We look more promising than our parent at this depth
                if this_health > best_depths[this_depth]:
                    if cc not in weights:
                        print(f"ERROR: {cc} not in weights when we thought it would be?")
                        continue
                    better_options[this_depth] = cc
                    best_depths[this_depth] = this_health

            # Now we look through better_options and select the lowest depth with a config
            if len(better_options):
                new_best = better_options[min(better_options.keys())]
                print(f"Found a better option: {new_best} at depth {min(better_options.keys())} vs {best}. Replacing")
                best = new_best

        if False:
            # Check parent chain for more promising branches - disabled for now, may be worth testing?
            # Now look and see if there's a more promising parent somewhere off our chain from the root
            # i.e., if we have
            # root -> unexplored config with estimated score 1000
            # root -> config with score 100 -> this config with estimated score 1010
            # we should select the unexplored config because it beat our parent
            parent_chain = []
            parent = self.graph.get_parent_config(best)
            while parent:
                parent_chain.append(parent)
                parent = self.graph.get_parent_config(parent)

            # Now look from root down to our parent
            for (grandparent, parent) in zip(parent_chain[::-1], parent_chain[::-1][1:]):

                unexplored_siblings = [x for x in self.graph.get_child_configs(grandparent) \
                                        if x != parent \
                                            and not x.run \
                                            and x not in self.pending_runs]

                # We've run 'parent' before and we have a concrete health score
                # We want to compare this to any unexplored siblings' estimated health scores
                parent_score = parent.health_score

                best_sibling = None
                best_sibling_score = 0
                for sibling in unexplored_siblings:
                    sibling_score = self.graph.calculate_expected_config_health(sibling)
                    if  sibling_score > best_sibling_score:
                        best_sibling_score = sibling_score
                        best_sibling = sibling

                if best_sibling_score > parent_score:
                    # We found a better sibling. We'll select that instead
                    print(f"Instead of {best} we're selecting {best_sibling} from parent chain as it's more promising")
                    best = best_sibling
                    break

        if True:
            # XXX a config should depend on a mitigation being tested, not a specific instance of a config with the mitigation applied!

            # Now, if we've selected a config that has dependencies, we'll select the most promising instead
            if any([cc in self.pending_runs or not cc.run for cc in best.dependencies]):
                # First pass - remove anything in self.pending_runs or anything with a .run property
                best.dependencies = set([cc for cc in best.dependencies if cc not in self.pending_runs and not cc.run])

            if len(best.dependencies):
                # We found a node we want to run. But it has dependencies. Select the most promising one
                # and run that instead
                for cc, weight in sorted_weights:
                    if cc in best.dependencies:

                        # This dependency points us to a fail->mitigation->config. But there may be other fail->mitigation->OTHERCONFIGs
                        # at this point - if those have been run, we can ignore this dependency since we've tried it before
                        dep_fail = self.graph.get_parent_failure(cc)
                        dep_mit = self.graph.get_parent_mitigation(cc)

                        # If there's a weight between the failure and the mitigation we know it has been run
                        # and we can skip
                        if len(self.graph.graph[dep_fail.gid][dep_mit.gid].get('weights', [])) > 0:
                            print(f"Skip dependency: {cc} as we've already run something similar")
                            best.dependencies.remove(cc)
                            continue

                        best.dependencies.remove(cc) # Old best no longer has this dep since we're popping it
                        best = cc
                        break
                else:
                    best.dependencies = set() # Clear out dependencies if we can't find a good one

        if best in self.pending_runs:
            print(f"ERROR: selected best config that's already pending: {best}")

        return best, weights[best]

    def calculate_config_depth(self, cc):
        # How many parents does this config have?
        depth = -1
        while cc:
            depth += 1
            cc = self.graph.get_parent_config(cc)
        return depth

def run_test():
    '''
    Use stubs to simulate running configs, identifying failures, finding mitigations,
    and applying them.
    '''
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
            "config_A0": { # Still has failure B (Fixed A)
                "failures":
                    [Failure("failure_B", "stub", {"some_data": "other_value"})],
                "health_score": 60
            },
            "config_A1": { # Still has failure A and B (Fixed nothing)
                "failures":
                    [Failure("failure_A", "stub", {"some_data": "some_value"}),
                     Failure("failure_B", "stub", {"some_data": "some_value"})],
                "health_score": 30
            },
            "config_B0": { # Still has failure A (Fixed B)
                "failures":
                    [Failure("failure_A", "stub", {"some_data": "some_value"})],
                "health_score": 100
            },
            "config_B1": { # Still has failure A and B (Fixed nothing)
                "failures":
                    [Failure("failure_A", "stub", {"some_data": "some_value"}),
                     Failure("failure_B", "stub", {"some_data": "other_value"})],
                "health_score": 30
            },

            "config_A0B": {
                "failures": [],
                "health_score": 110
            },

            "config_B0A": {
                "failures":
                    # A new failure emerges!
                    [Failure("failure_B0A", "stub", {"some_data": "other_value"})],
                "health_score": 100
            },

            # Given config B2A, we'll find config C which works.
            "config_C": {
                "failures": [],
                "health_score": 3000
            }
        }

        try:
            return stubs[config.friendly_name]["failures"], stubs[config.friendly_name]["health_score"]
        except KeyError:
            raise ValueError(f"NYI SIMULATION OF RUN CONFIG: {config}")

    def find_mitigations_f(failure : Failure, config : Configuration) -> List[Mitigation]:
        '''
        Given a failure and a config, identify mitigations that could be applied.
        This should be deterministic - if two failures have the same mitigations
            they should produce the same mitigations - but the data may be distinct.
            Graph will need to combine the data
        '''
        # First check for specific instances of the faiulres where we say they're different?
        if failure.friendly_name == "failure_B" and config.friendly_name == 'config_A0':
            # We ran mitigation A0 to fix failure A. Now we're trying to fix B
            return [Mitigation("mitigation_A0B", "mitigation", {"some_data": "some_value"})]
        elif failure.friendly_name == "failure_A" and config.friendly_name == 'config_B0':
            # We ran mitigation B0 to fix failure B. Now we're trying to fix A
            return [Mitigation("mitigation_B0A", "mitigation", {"some_data": "some_value"})]

        # Now some catch-alls
        elif failure.friendly_name == "failure_A":
            return [Mitigation("mitigation_A0", "mitigation", {"some_data": "some_value"}),
                    Mitigation("mitigation_A1", "mitigation", {"some_data": "other_value"})]
        elif failure.friendly_name == "failure_B":
            return [Mitigation("mitigation_B0", "mitigation", {"some_data": "some_value"}),
                    Mitigation("mitigation_B1", "mitigation", {"some_data": "other_value"})]

        elif failure.friendly_name == "failure_B0A": # and config.friendly_name == 'config_B0A':
            return [Mitigation("mitigation_B0A", "mitigation", {"some_data": "some_value"})]

        elif failure.friendly_name == "failure_C":
            return []
        else:
            raise ValueError(f"NYI SIMULATION OF FIND MITIGATIONS FOR: {failure} from {config}")

    def find_new_configs_f(failure : Failure, mitigation : Mitigation, parent_config : Configuration) -> List[Configuration]:
        '''
        Given a failure and a mitigation, find any new configurations that could be derived
        from the parent config. Return list of new configs
        '''
        # STUB
        if failure.friendly_name == 'failure_A' and parent_config.friendly_name == 'config_0':
            if mitigation.friendly_name == 'mitigation_A0':
                return [ Configuration("config_A0", {"some_data": "some_value"})]

            elif mitigation.friendly_name == 'mitigation_A1':
                return [Configuration("config_A1", {"some_data": "some_value"})]

        elif failure.friendly_name == 'failure_B' and parent_config.friendly_name == 'config_0':
            if mitigation.friendly_name == 'mitigation_B0':
                return [Configuration("config_B0", {"some_data": "some_value"})]
            elif mitigation.friendly_name == 'mitigation_B1':
                return [ Configuration("config_B1", {"some_data": "some_value"})]

        elif failure.friendly_name == 'failure_A' and parent_config.friendly_name == 'config_B0':
            # We ran mitigation B0 to fix failure B. Now we're trying to fix A
            if mitigation.friendly_name == 'mitigation_B0A':
                return [Configuration("config_B0A", {"some_data": "some_value"})]

        elif failure.friendly_name == 'failure_B' and parent_config.friendly_name == 'config_A0':
            if mitigation.friendly_name == 'mitigation_A0B':
                return [Configuration("config_A0B", {"some_data": "some_value"})]

        elif failure.friendly_name == 'failure_B0A' and parent_config.friendly_name == 'config_B0A':
            if mitigation.friendly_name == 'mitigation_B0A':
                return [Configuration("config_C", {"some_data": "some_value"})]

        return []



    config_manager = ConfigurationManager(base_config)

    # Run a series of exploration cycles
    for i in range(15):
        if not config_manager.run_exploration_cycle(run_config, find_mitigations_f, find_new_configs_f):
            break
        config_manager.graph.create_png(f"/results/config_graph{i}.png")

    # Visualize the resulting graph
    config_manager.graph.create_png("/results/config_graph.png")

if __name__ == "__main__":
    run_test()
