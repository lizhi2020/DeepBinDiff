import json
import os
import numpy as np
import utility
import config
import tensorflow
from config import dbdlogger

def pre_matching(embedding_file: str,node_file: str, toBeMergedBlocks={}):
    ebd_dic = utility.ebd_file_to_dic(embedding_file)
    with open(node_file,'r') as fp:
        node_in_bin1, _ = json.load(fp) 
    
    bin1_mat = []
    bin2_mat = []
    node_map = {}
    for idx, line in ebd_dic.items():
        if idx < node_in_bin1:
            bin1_mat.append(line)
            node_map[str(idx)] = len(bin1_mat) - 1
        else:
            bin2_mat.append(line)
            node_map[str(idx)] = len(bin2_mat) - 1

    bin1_mat = np.array(bin1_mat,dtype=np.float32)
    bin2_mat = np.array(bin2_mat,dtype=np.float32)

    tensorflow.compat.v1.disable_eager_execution()
    dbdlogger.info('disable eager execution')
    sim_result = utility.similarity_gpu(bin1_mat, bin2_mat)
    dbdlogger.info(f'preform matching: to be merged {len(toBeMergedBlocks)}')
    matched_pairs, inserted, deleted = utility.matching(node_in_bin1, ebd_dic, sim_result, node_map, toBeMergedBlocks)
    dbdlogger.info(f'matched pairs: {matched_pairs}')
