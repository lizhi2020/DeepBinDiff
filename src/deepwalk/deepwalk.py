import sys
import random
import logging

from deepwalk import graph

logger = logging.getLogger(__name__)
LOGFORMAT = "%(asctime).19s %(levelname)s %(filename)s: %(lineno)s %(message)s"
# useless?
def debug(type_, value, tb):
  if hasattr(sys, 'ps1') or not sys.stderr.isatty():
    sys.__excepthook__(type_, value, tb)
  else:
    import traceback
    import pdb
    traceback.print_exception(type_, value, tb)
    print(u"\n")
    pdb.pm()

# number_walks: number of walks per node
# walk_length: the length of each random walk
# seed: random seed
def process(edgelistFile, undirected=False, number_walks=2, walk_length=4, seed=0):
  G = graph.load_edgelist(edgelistFile, undirected=undirected)

  print("Number of nodes: {}".format(len(G.nodes())))
  num_walks = len(G.nodes()) * number_walks
  print("Number of walks: {}".format(num_walks))
  data_size = num_walks * walk_length
  print("Data size (walks*length): {}".format(data_size))

  print("Walking...")
  walks = graph.build_deepwalk_corpus(G, num_paths=number_walks, path_length=walk_length, alpha=0, rand=random.Random(seed)) 
  return walks