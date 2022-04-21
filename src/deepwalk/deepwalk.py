import random
from deepwalk import graph

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