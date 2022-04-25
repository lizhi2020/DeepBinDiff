import random,config
import networkx as nx
from deepwalk import graph

# 对一个图生成walk 没有随机打乱
# 返回值是一个二维数组 方便调用方打乱
class MyGraph:
    def __init__(self,g: nx.DiGraph) -> None:
        self.g=g
    def _random_walk(self,path_length,rand: random.Random,alpha,start):
        path = [start]

        # Sampling is uniform w.r.t V, and not w.r.t E
        # path = [rand.choice(list(G.keys()))]
        for i in range(path_length):
            cur = path[i]
            succ = list(self.g.successors(cur))
            if succ:
                if rand.random() >= alpha:
                    path.append(rand.choice(succ))
                else:
                    path.append(path[0])
            else:
                break
        return path

    def build_deepwalk(self,num,path_length,alpha=0,seed=0):
        walks = []
        rand=random.Random(seed)
        nodes = list(self.g.nodes())
        
        for _ in range(num):
            for node in nodes:
                walks.append(self._random_walk(path_length, rand=rand, alpha=alpha, start=node))
        
        return walks
        

# number_walks: number of walks per node
# walk_length: the length of each random walk
# seed: random seed
def process(edgelistFile, undirected=False, number_walks=2, walk_length=4, seed=0):
    G = graph.load_edgelist(edgelistFile, undirected=undirected)

    config.dbdlogger.info("Number of nodes: {}".format(len(G.nodes())))
    num_walks = len(G.nodes()) * number_walks
    config.dbdlogger.info("Number of walks: {}".format(num_walks))
    data_size = num_walks * walk_length
    config.dbdlogger.info("Data size (walks*length): {}".format(data_size))

    config.dbdlogger.info("Walking...")
    walks = graph.build_deepwalk_corpus(G, num_paths=number_walks, path_length=walk_length, alpha=0, rand=random.Random(seed)) 
    return walks