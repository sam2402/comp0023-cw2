#! /usr/bin/python3

import sys
from optparse import OptionParser, OptionValueError
import networkx as nx

# TODO: optionally, add the description of your strategy for stage 3 here. 
# <a few sentences>

########
# Main #
########

def compute_paths(igp_filename: str, pairs_filename: str, lans_filename: str = None):
    igp_network, id_labels = generate_graph(igp_filename)
    pairs = get_pairs(pairs_filename)
    shortest_paths = {
        pair_id: nx.all_shortest_paths(igp_network, id_labels[pair[0]], id_labels[pair[1]], weight="weight") for pair_id, pair in pairs.items()
    }
    for pair_id, paths in shortest_paths.items():
        output_path(pair_id, paths, id_labels)

def output_path(pair_id: str, paths: list[list[int]], id_labels: dict) -> None:
    paths = "; ".join(format_path(path, id_labels) for path in paths)
    print(f"{pair_id}:", paths)

def format_path(path: list[int], id_labels):
    return " -> ".join(map(lambda node: id_labels[node], path))

def get_pairs(filename: str) -> dict[str: tuple[str, str]]:
    pairs = {}
    with open(filename, 'r') as f:
        for line in f:
            if line == "\n":
                continue
            pair_id = line.split(":")[0]
            src_label = line.split(" ")[1]
            dest_label = line.split(" ")[2].strip()
            pairs[pair_id] = (src_label, dest_label)
        return pairs

def generate_graph(filename: str) -> nx.Graph:
    with open(filename, 'r') as f:
       lines = f.read().splitlines()
    
    graph = nx.DiGraph()
    id_labels = {}
    node_count = int(lines[0].split(" ")[1])
    for node_line in lines[2:node_count+2]:
        id = int(node_line.split(" ")[0])
        label = node_line.split(" ")[1]
        id_labels[id] = label
        id_labels[label] = id
        graph.add_node(id, label=label)
    
    edge_start_line_index = node_count+3
    edge_count = int(lines[edge_start_line_index].split(" ")[1])
    for edge_line in lines[edge_start_line_index+2:edge_start_line_index+edge_count+2]:
        edge_data = edge_line.split(" ")
        label = edge_data[0]
        src = int(edge_data[1])
        dest = int(edge_data[2])
        weight = int(edge_data[3])
        bw = int(edge_data[4])
        delay = int(edge_data[5])

        graph.add_edge(src, dest, weight=weight, bw=bw, delay=delay)
    
    return graph, id_labels


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
    if command not in ['compute-paths','compute-maxload','optimize-weights']:
        parser.print_help()
        sys.exit()

    # TODO
    # <your code>
    if command == "compute-paths":
        compute_paths(igpfile, pathsfile, lansfile)


