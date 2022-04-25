import json
import logging
import math
import os
import random
import tempfile
import tensorflow as tf
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from functools import reduce
from typing import List
import networkx as nx
import angr
import numpy as np
import pyvex

import config
import featureGen
import matching_driver
import preprocessing
from deepwalk import deepwalk

# 对于block为空的节点也会生成embedding
# 返回List[embedding]
def cal_node_embeddings(nodes,blocks_pre_opcode,tokenEmbeddings,token_dict,uniform):
    node_embeddings = []
    for node in nodes:
        opcode_embeddings = [np.zeros(64)]
        oprand_embeddings = [np.zeros(64)]
        if node.block and len(node.block.vex.statements):
            for stmt in node.block.vex.statements:
                list_ = list(stmt.expressions)
                opcode_embeddings.append(tokenEmbeddings[token_dict[uniform(stmt)]])
                oprand_embeddings+=[tokenEmbeddings[token_dict[uniform(i)]] for i in list_]
        opcode_embeddings=np.array(opcode_embeddings).sum(0)
        oprand_embeddings=np.array(oprand_embeddings).sum(0)
        node_embed = np.concatenate((opcode_embeddings,oprand_embeddings),axis=0)
        node_embeddings.append(node_embed)
    return node_embeddings

# todo 省略id 使用json
def feature_vec_file_gen(feature_file, block_embeddings):
    with open(feature_file,'w') as feaVecFile:
        for index,embed in enumerate(block_embeddings):
            feaVecFile.write(str(index)+" ")
            for k in embed:
                feaVecFile.write(str(k)+" ")
            feaVecFile.write("\n")

# todo: imark constant str ptr处理!!!
def vex_uniform1(ob):
    if isinstance(ob, pyvex.stmt.IRStmt):
        return ob.tag_int
    else:
        return ob

def vex_uniform2(ob):
    return ob.tag_init

def vex_uniform3(ob):
    if isinstance(ob, pyvex.stmt.IRStmt):
        return ob.tag_int
    elif isinstance(ob, pyvex.expr.Const):
        return ob.tag_int
    return ob

def vex_uniform4(ob):
    if isinstance(ob, pyvex.expr.Const):
        return ob
    return ob.tag_int

def collect_tokens(cfg: angr.analyses.CFG,uniform=None):
    graph = cfg.graph
    tokens = set()
    for node in graph.nodes:
        if node.block:
            bb: angr.Block = node.block
            for stmt in bb.vex.statements:
                tokens.add(uniform(stmt) if uniform else stmt)
                for expression in stmt.expressions:
                    tokens.add(uniform(expression) if uniform else expression)
    return tokens

def generateTrainData(article,dict_,uniform):
    stmts = [None]
    ctxs = []
    targets = []
    for node in article:
        if node.block:
            stmts.extend([stmt for stmt in node.block.vex.statements if not isinstance(stmt, pyvex.stmt.IMark)])
        else:
            stmts.append(None)
    stmts.append(None)
    for i in range(1,len(stmts)-1):
        if not stmts[i]:
            continue
        stmt_ctx=[stmts[i-1],stmts[i+1]]
        ctx=[[ 0 for _ in range(7) ] for i in range(2)]
        for j in [0,1]:
            if stmt_ctx[j]:
                exprs = list(map(uniform,[stmt_ctx[j]]+list(stmt_ctx[j].expressions)) )
                assert len(exprs) <= 7, (list(stmt_ctx[j].expressions),exprs)
                for ii in range(len(exprs)):
                    ctx[j][ii]=dict_[exprs[ii]]

        exprs = list(map(uniform,[stmts[i]]+list(stmts[i].expressions)))
        for expr_ in exprs:
            ctxs.append(ctx)
            targets.append(dict_[expr_])
    return ctxs,targets

def generate_neiborhood(nodes,node_dict):
    for node in nodes:
        if not node.block:
            continue
        id=node_dict[node]
        pre = [node_dict[n] for n in node.predecessors if n.block]
        suc = [node_dict[n] for n in node.successors if n.block]
        preprocessing.per_block_neighbors_bids[id] = [pre,suc]
        if id < 617:
            for i in pre+suc:
                assert i<617,(id,node_dict[node],pre,suc)
        else:
            for i in pre+suc:
                assert i>=617,(id,pre.suc)

def main():
    parse = ArgumentParser()
    parse.add_argument('input1')
    parse.add_argument('input2')
    parse.add_argument('-o','--output')

    args = parse.parse_args()
    inputs = [args.input1, args.input2]

    cfgs = [preprocessing.getCFG(i) for i in inputs]

    nodes1, nodes2 = [list(cfg.graph.nodes) for cfg in cfgs]
    nodes = nodes1 + nodes2
    node_dict1 = dict((node,id) for id,node in enumerate(nodes1))
    node_dict2 = dict((node,id) for id,node in enumerate(nodes2,len(nodes1)))

    toBeMergedBlocks = preprocessing.get_merge_nodes(cfgs,[preprocessing.path_leaf(i) for i in inputs],[node_dict1,node_dict2])    

    # 字典
    vex_uniform=vex_uniform3
    vocab = reduce(lambda x,y: x|y,[collect_tokens(i,uniform=vex_uniform) for i in cfgs])
    dict_ = dict(zip(vocab,range(1,1+len(vocab))))
    # 随机游走
    graphs = [deepwalk.MyGraph(i.graph) for i in cfgs]
    walks = [i.build_deepwalk(num=2,path_length=5) for i in graphs]
    walks = reduce(lambda x,y:x+y,walks)
    
    # 随机打乱
    random.shuffle(walks)
    article = [node  for walk_ in walks for node in walk_]

    # 生成训练数据
    ctx_data, target_data = generateTrainData(article,dict_,vex_uniform)
    ctx_data = np.array(ctx_data)
    target_data = np.array(target_data)
    data = tf.data.Dataset.from_tensor_slices((ctx_data,target_data))
    # token embedding
    tokenEmbeddings = featureGen.generate_token_embeddings(data,len(vocab))

    # block embedding
    block_embeddings = cal_node_embeddings(nodes,None,tokenEmbeddings,dict_,vex_uniform)

    feature_vec_file_gen(config.file.features_file, block_embeddings)

    # 检查返回值
    # !!python3
    preprocessing.edgeListGen(cfgs, [node_dict1,node_dict2], config.file.edgelist_file)
    tadw_command = "python ./src/performTADW.py --method tadw --input " + config.file.edgelist_file + " --graph-format edgelist --feature-file " + config.file.features_file + " --output "+config.file.embedding_file
    os.system(tadw_command) 

    generate_neiborhood(nodes1,node_dict1)
    generate_neiborhood(nodes2,node_dict2)
    matching_driver.pre_matching(config.file.embedding_file,cfgs[0].graph.number_of_nodes(), toBeMergedBlocks)

if __name__ == "__main__":
    main()
