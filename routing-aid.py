#! /usr/bin/python3

from collections import deque
import math
import sys
from optparse import OptionParser
import networkx as nx
import itertools

# TODO: optionally, add the description of your strategy for stage 3 here. 
# <a few sentences>

# I leveraged two main insights in stage 3 and created a function for each of these approaches that each outputs a network with new weights.
# The maximal load is computed for each of these networks, and the returned IGP weights are those that correspond to the minimum maximal link load.
# These insights were:
#     1. The flow should be penalised for using links with low bandwidth.
#     2. The flow should have maximal branching so as to minimise the load on any one link.

# For 1, each link weight is set to be proportional to the inverse of its bandwidth.
# This is done by computing the lowest common multiple of all link bandwidths and then setting the link weight to LCM//bw.

# Approach two is related to a problem known as equal-cost multi-path routing.
# I initially aimed write a function that would return a graph for each demand, where all paths from source to target have equal weight.
# The next stage would then have been to combine these graphs into one graph while preserving the respective equal costs. 

# When paths share nodes, even the first part of this problem is hard and as such I adopted a more heuristic approach.
# I found all paths from source to target and set the weight of each edge to be proportional to the inverse of the path length.
# Depending on the topography of the graph, first sorting the paths from longest to shortest or vice verse can yield better results so both are performed \
# and the returned graph is that which has the minimum maximal link load.

# Approach two works particularly well in cases where there is only one demand, but generally yields improvements across the test cases;
# and approach one works well in cases with more complex networks and more demands such as tests 9 and 10 where it is very close to or matches the baseline solution.

########
# Main #
########

NodeIdentifier = str

### OPTIMIZE

def optimize_weights(demands: list[(NodeIdentifier, NodeIdentifier, int)], network: nx.DiGraph) -> nx.DiGraph:
    return min(
        (
            *(set_all_paths_to_equal_weight(network, demand) for demand in demands),
            *(set_all_paths_to_equal_weight(network, demand, reverse_sort=False) for demand in demands),
            set_all_weights_to_inverse_bw(network),
            network
        ),
        key=lambda graph: compute_maxload(demands, graph)[0]
    )

def set_all_paths_to_equal_weight(network: nx.DiGraph, demand: (NodeIdentifier, NodeIdentifier, int), reverse_sort=True) -> nx.DiGraph:
    new_network = network.copy()
    (src, dest, _) = demand
    paths = sorted(nx.all_simple_edge_paths(network, source=src, target=dest), key=len, reverse=reverse_sort)
    path_lens_lcm = math.lcm(*map(len, paths))

    for path in paths:
        for a, b in path:
            new_network[a][b]["weight"] = path_lens_lcm//len(path)
    return new_network

def set_all_weights_to_inverse_bw(network: nx.DiGraph) -> nx.DiGraph:
    new_network = network.copy()
    bandwidth_lcm = math.lcm(*(edge_data[2]["bw"] for edge_data in network.edges.data()))
    for src, dest in network.edges:
        new_network[src][dest]["weight"] = bandwidth_lcm//new_network[src][dest]["bw"]
    return new_network

### COMPUTE MAX LOADS

def compute_maxload(demands: list[(NodeIdentifier, NodeIdentifier, int)], network: nx.DiGraph) -> (float, list[(NodeIdentifier, NodeIdentifier)]):
    load_graphs = [compute_loads(demand, network) for demand in demands]
    edge_loads = {}
    for load_graph in load_graphs:
        for a, b, attrs in load_graph.edges.data():
            if (a, b) not in edge_loads:
                edge_loads[(a, b)] = 0
            edge_loads[(a, b)] += attrs["load"]
    edge_bandwidths = nx.get_edge_attributes(network, "bw") | (nx.get_edge_attributes(network.graph["lan"], "bw") if network.graph["lan"] is not None else {})
    edge_percentages = {edge: load/edge_bandwidths[edge] for edge, load in edge_loads.items()}

    max_edges = set()
    max_load = -1
    for edge, load in edge_percentages.items():
        if load > max_load:
            max_load = load
            max_edges = set([edge])
        elif load == max_load:
            max_edges.add(edge)

    return max_load, max_edges

def compute_loads(demand: (NodeIdentifier, NodeIdentifier, int), network: nx.DiGraph) -> nx.DiGraph:
    paths_graph = make_path_graph(network, demand[0], demand[1])
    return propagate_load(paths_graph, demand[0], demand[2])

def propagate_load(paths_graph: nx.DiGraph, src: NodeIdentifier, load: int) -> nx.DiGraph:
    node_queue: deque[(NodeIdentifier, int)] = deque([(src, load)])
    load_graph = paths_graph.copy()
    while len(node_queue) > 0:
        curr_node, curr_load = node_queue.popleft()
        successor_nodes = list(paths_graph.successors(curr_node))
        for successor_node in successor_nodes:
            new_load = curr_load/len(successor_nodes)
            node_queue.append((successor_node, new_load))
            load_graph[curr_node][successor_node]["load"] += new_load
    return load_graph

def make_path_graph(network: nx.DiGraph, src: NodeIdentifier, dest: NodeIdentifier) -> nx.DiGraph:
    paths = compute_paths({"pairId": (src, dest)}, network)["pairId"]
    path_graph: nx.DiGraph = nx.create_empty_copy(network)
    for path in paths:
        for a, b in zip(path, path[1:]):
            path_graph.add_edge(a, b)
            edge_data = network.get_edge_data(a, b) if (a, b) in network.edges() else network.graph["lan"].get_edge_data(a, b)
            for attr, val in edge_data.items():
                path_graph[a][b][attr] = val
            path_graph[a][b]["load"] = 0
    return path_graph

### COMPUTE PATHS

def compute_paths(pairs: dict[str, (NodeIdentifier, NodeIdentifier)], network: nx.DiGraph) -> dict[str, list[list[NodeIdentifier]]]:
    # Compute shortest path over WAN
    shortest_paths: dict[str, list[NodeIdentifier]] = {
        pair_id: list(nx.all_shortest_paths(network, pair[0], pair[1], weight="weight")) for pair_id, pair in pairs.items()
    }

    # For all paths check if the links between two adjacent nodes are LANs,
    # if so, traverse the LAN and insert the path between the two WAN nodes
    for paths in shortest_paths.values():
        for path_index, path in enumerate(paths):
            lan_paths = {}
            for hop1, hop2 in zip(path, path[1:]):
                if network[hop1][hop2]["lan"] is not None:
                    lan_paths[(hop1, hop2)] = get_intra_lan_path(network[hop1][hop2]["lan"], hop1, hop2)
            
            # Insert lan path into wan path
            new_path = path.copy()
            i = 0
            while i < len(new_path)-1:
                hop1 = new_path[i]
                hop2 = new_path[i+1]
                if (hop1, hop2) in lan_paths:
                    new_path[i+1:i+1] = lan_paths[(hop1, hop2)][1:-1]
                i += 1
            
            paths[path_index] = new_path            

    return {path_id: list(filter(lambda path: len(path) == len(set(path)), paths)) for path_id, paths in shortest_paths.items()}

def filter_paths(graph: nx.DiGraph, paths: list[list[NodeIdentifier]]) -> list[NodeIdentifier]:
    id_lists = [list(map(lambda node: nx.get_node_attributes(graph, "id")[node], path)) for path in paths]
    min_path_index = id_lists.index(min(id_lists))
    return paths[min_path_index]

def create_spanning_tree(lan: nx.DiGraph) -> nx.DiGraph:
    root_node = min(lan.nodes.data(), key=lambda node: node[1]["id"])[0]
    
    spanning_tree: nx.DiGraph = nx.create_empty_copy(lan)
    shortest_paths = {
        node: filter_paths(lan, list(nx.all_shortest_paths(lan, node, root_node, weight="weight"))) for node in lan.nodes
    }
    for path in shortest_paths.values():
        spanning_tree.add_edges_from([(a, b) for a, b in zip(path, path[1:])], bw=0)
        spanning_tree.add_edges_from([(b, a) for a, b in zip(path, path[1:])], bw=0)
    for a, b in spanning_tree.edges:
        spanning_tree[a][b]["bw"] = lan[a][b]["bw"]

    return spanning_tree

def get_intra_lan_path(tree: nx.DiGraph, src: NodeIdentifier, dest: NodeIdentifier) -> list[NodeIdentifier]:

    root = min(tree.nodes.data(), key=lambda node: node[1]["id"])[0]

    path_to_root = nx.shortest_path(tree, src, root)
    path_from_root = nx.shortest_path(tree, root, dest)[1:]

    visited = {}
    path = []
    for index, node in enumerate(path_to_root + path_from_root):
        if node in visited:
            prev_occurrence_index = visited[node]
            path = path[:prev_occurrence_index]
        visited[node] = index
        path.append(node)
    return path

def merge_networks(igp_network: nx.DiGraph, lan_network: nx.DiGraph) -> nx.DiGraph:
    shared_node_ids = set(igp_network.nodes).intersection(set(lan_network.nodes))

    graph = igp_network.copy()
    graph.graph["lan"] = lan_network
    for src, dest in itertools.combinations(shared_node_ids, 2):
        graph[src][dest]["lan"] = lan_network
        graph[dest][src]["lan"] = lan_network

    return graph

def get_node_label_from_id(graph: nx.DiGraph, id: int) -> NodeIdentifier:
    for node in graph.nodes.data():
        if node[1]["id"] == id:
            return node[0]
    raise ValueError(f"No such node with id: {id}")

### PARSING

def parse_network_files(igp_filename: str, lans_filename: str = None) -> nx.DiGraph:
    igp_network = parse_graph_file(igp_filename)
    lan_spanning_tree = create_spanning_tree(parse_graph_file(lans_filename, is_lan=True)) if lans_filename is not None else None
    return merge_networks(igp_network, lan_spanning_tree) if lan_spanning_tree is not None else igp_network

def parse_graph_file(filename: str, is_lan = False) -> nx.DiGraph:
    if filename == None:
        return None

    with open(filename, "r") as f:
       lines = f.read().splitlines()
    
    # Add nodes
    graph = nx.DiGraph()
    id_labels = {}
    node_count = int(lines[0].split(" ")[1])
    for node_line in lines[2:node_count+2]:
        id = int(node_line.split(" ")[0])
        label = node_line.split(" ")[1]
        id_labels[id] = label
        graph.add_node(label, id=id)
    
    # Add edges
    edge_start_line_index = node_count+3
    edge_count = int(lines[edge_start_line_index].split(" ")[1])
    for index, edge_line in enumerate(lines[edge_start_line_index+2:edge_start_line_index+edge_count+2]):
        edge_data = edge_line.split(" ")
        label = edge_data[0]
        src = int(edge_data[1])
        dest = int(edge_data[2])
        weight = int(edge_data[3]) if not is_lan else None
        bw = int(edge_data[4]) if not is_lan else int(edge_data[3])
        delay = int(edge_data[5]) if not is_lan else None

        graph.add_edge(id_labels[src], id_labels[dest], position=index, label=label, bw=bw, lan=None)
        if not is_lan:
            nx.set_edge_attributes(graph, {
                (id_labels[src], id_labels[dest]): {"weight":weight, "delay":delay}
            })
    
    graph.graph["lan"]: nx.DiGraph | None = None
    return graph

def parse_pairs_file(filename: str) -> dict[str: (NodeIdentifier, NodeIdentifier)]:
    pairs = {}
    with open(filename, "r") as f:
        for line in f:
            if line == "\n":
                continue
            pair_id = line.split(":")[0]
            src_label = line.split(" ")[1]
            dest_label = line.split(" ")[2].strip()
            pairs[pair_id] = (src_label, dest_label)
        return pairs

def parse_demands_file(filename: str, graph: nx.DiGraph) -> list[(NodeIdentifier, NodeIdentifier, int)]:
    with open(filename, "r") as f:
       lines = f.read().splitlines()
    
    demands = []
    demand_count = int(lines[0].split(" ")[1])
    for demand_line in lines[2:demand_count+2]:
        demand_data = demand_line.split(" ")
        demands.append((
            get_node_label_from_id(graph, int(demand_data[1])),
            get_node_label_from_id(graph, int(demand_data[2])),
            int(demand_data[3])
        ))
    return demands

def output_pair_paths(pair_id: str, paths: list[list[NodeIdentifier]]) -> None:
    paths = "; ".join(" -> ".join(path) for path in paths)
    print(f"{pair_id}:", paths)

def output_graph(graph: nx.DiGraph) -> None:
    print(f"NODES {len(graph.nodes)}")
    print("id label")
    for node_label, attrs in sorted(graph.nodes.data(), key=lambda node: node[1]['id']):
        print(f"{attrs['id']} {node_label}")
    print("")
    print(f"EDGES {len(graph.edges)}")
    print("label src dest weight bw delay")
    for src_label, dest_label, attrs in sorted(graph.edges.data(), key=lambda edge: edge[2]['position']):
        src_id = graph.nodes[src_label]["id"]
        dest_id = graph.nodes[dest_label]["id"]
        print(f"{attrs['label']} {src_id} {dest_id} {attrs['weight']} {attrs['bw']} {attrs['delay']}")

if __name__ == "__main__":
    # setup CLI parser
    commands_descriptions = "Commands: " + \
                            "\n  compute-paths\n\t[compute and print paths, requires -i and -p options]" + \
                            "\n  compute-maxload\n\t[compute and print max link load and max loaded links, requires -i and -d options]" + \
                            "\n  optimize-weights\n\t[compute and saves IGP weights that reduce max link load, requires -i and -d options]"
    usage = "usage: %prog <command> [<command-options>]\n\n{}".format(commands_descriptions)
    parser = OptionParser(usage=usage)
    parser.add_option("-i", "--igpfile", dest="igpfile", type="string", metavar="IGP_FILENAME",
                        help="set filename with the IGP topology and link weights")
    parser.add_option("-l", "--lansfile", dest="lansfile", type="string", metavar="LANS_FILENAME",
                        help="set filename with the topology of network LANs")
    parser.add_option("-p", "--pairsfile", dest="pathsfile", type="string", metavar="PAIRS_FILENAME",
                        help="set filename including the source-destination pairs for which paths have to be computed")
    parser.add_option("-d", "--demandsfile", dest="demandsfile", type="string", metavar="DEMANDS_FILENAME",
                        help="set filename with traffic demands")

    # parse options
    (options, args) = parser.parse_args()
    igpfile = options.igpfile
    lansfile = options.lansfile
    pathsfile = options.pathsfile
    demandsfile = options.demandsfile

    # parse arguments
    if len(args) < 1:
        parser.print_help()
        sys.exit()
    command = sys.argv[1]
    if command not in ["compute-paths", "compute-maxload", "optimize-weights"]:
        parser.print_help()
        sys.exit()

    # TODO
    # <your code>
    if command == "compute-paths":
        pairs = parse_pairs_file(pathsfile)
        network = parse_network_files(igpfile, lansfile)
        for pair_id, paths in compute_paths(pairs, network).items():
            output_pair_paths(pair_id, paths)
    elif command == "compute-maxload":
        network = parse_network_files(igpfile, lansfile)
        demands = parse_demands_file(demandsfile, network)
        max_link_load, max_loaded_links = compute_maxload(demands, network)
        print(f"Max link load: {round(max_link_load*100, 1)}%")
        print(f"Max loaded links: {'; '.join([f'{a} -> {b}' for (a, b) in max_loaded_links])}")
    elif command == "optimize-weights":
        network = parse_network_files(igpfile, lansfile)
        demands = parse_demands_file(demandsfile, network)
        new_network = optimize_weights(demands, network)
        max_link_load, max_loaded_links = compute_maxload(demands, new_network)
        print(f"Post-optimization max link load: {round(max_link_load*100, 1)}%")
        print(f"Post-optimization max loaded links: {'; '.join([f'{a} -> {b}' for (a, b) in max_loaded_links])}")
        print("")
        output_graph(new_network)

