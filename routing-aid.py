#! /usr/bin/python3

import sys
from optparse import OptionParser, OptionValueError
import networkx

# TODO: optionally, add the description of your strategy for stage 3 here. 
# <a few sentences>

########
# Main #
########

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



