import json
import logging
import math
import os
import random
import tempfile
import tensorflow as tf
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from functools import reduce
from platform import node
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


# 管理token 编号
class Dictionary:
    def __init__(self) -> None:
        self.tokens = set()
        self.reverse_dictionary = None
    def update(self, tokens):
        if isinstance(self.tokens,set):
            self.tokens.update(tokens)
        else:
            raise Exception('unable to update after toIndex()')
    def toIndex(self):
        self.tokens = list(self.tokens) # 转为列表是为了方便索引访问
        self.reverse_dictionary = dict(zip(self.tokens,range(len(self.tokens))))
    
    def __len__(self):
        return len(self.tokens)


# 构建字典 返回 set
def genDictionary(blockinfo_list: List[preprocessing.blockinfo]) -> Dictionary:
    res = Dictionary()
    for binfo in blockinfo_list:
        res.update(binfo.tokens)
    res.toIndex() # 生成索引后不可再更新
    return res

# blockIdxToTokens: blockIdxToTokens[block index] = token list
# return dictionary: index to token, reversed_dictionary: token to index
# 统计所有的token 然后编个号
# vocabulary 统计词频 允许有重复的token
# dictionary 无重复
# token仅仅只是一个字符串 reg8 mov imme 等等


# generate article for word2vec. put all random walks together into one article.
# we put a tag between blocks
# article = walk || walk || ... || walk
# walk = block || block || ... || block
# block = token || token || ... || token
# 最终存放的是token的id
def articlesGen(walks, blockinfo_list: List[preprocessing.blockinfo], dictionary: Dictionary):
    # stores all the articles, each article itself is a list
    article = [0,0,0,0]
    
    for walk in walks:
        # one random walk is served as one article
        for idx in walk:
            # idx should always <= len(blockinfo_list)
            tokens = blockinfo_list[int(idx)].tokens
            for token in tokens:
                article.append(dictionary.reverse_dictionary[token])
        
    insnStartingIndices = [0]
    for i in range(4,len(article)): 
        if dictionary.tokens[int(article[i])] in preprocessing.opcode_set:
            insnStartingIndices.append(i)
    assert insnStartingIndices[1] == 4
    article.append(0)
    tmp=len(article)-1
    insnStartingIndices += [tmp,tmp]
    # 这样前后一共加了3个指令
    return article, insnStartingIndices
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
# adopt TF-IDF method during block embedding calculation
def cal_block_embeddings(blockinfolist: List[preprocessing.blockinfo], insToBlockCounts, tokenEmbeddings, dictionary: Dictionary):
    block_embeddings = {}
    totalBlockNum = len(blockinfolist)

    for bid in range(totalBlockNum):
        binfo = blockinfolist[bid]
        tokenlist = binfo.tokens
        opcodeCounts = binfo.opcodeCount
        opcodeNum = binfo.total_insns

        opcodeEmbeddings = []
        operandEmbeddings = []

        if len(tokenlist) != 0:
            for token in tokenlist:
                tokenid = dictionary.reverse_dictionary[token]
                tokenEmbedding = tokenEmbeddings[tokenid]
                if token in preprocessing.opcode_set and token in opcodeCounts:
                    # here we multiple the embedding with its TF-IDF weight if the token is an opcode
                    tf_weight = opcodeCounts[token] / opcodeNum
                    x = totalBlockNum / insToBlockCounts[token]
                    idf_weight = math.log(x)
                    tf_idf_weight = tf_weight * idf_weight
                    # print("tf-idf: ", token, opcodeCounts[token], opcodeNum, totalBlockNum, insToBlockCounts[token], tf_weight, idf_weight)
                    opcodeEmbeddings.append(tokenEmbedding * tf_idf_weight)
                else:
                    operandEmbeddings.append(tokenEmbedding)

            opcodeEmbeddings = np.array(opcodeEmbeddings)
            operandEmbeddings = np.array(operandEmbeddings)

            opcode_embed = opcodeEmbeddings.sum(0)
            operand_embed = operandEmbeddings.sum(0)
        # set feature vector for null block node to be zeros
        else:
            embedding_size = 64
            opcode_embed = np.zeros(embedding_size)
            operand_embed = np.zeros(embedding_size)

        # !!!
        # if no operand, give zeros
        if operand_embed.size == 1:
            operand_embed = np.zeros(len(opcode_embed))
        
        block_embed = np.concatenate((opcode_embed, operand_embed), axis=0)
        block_embeddings[bid] = block_embed
    return block_embeddings

# todo 省略id 使用json
def feature_vec_file_gen(feature_file, block_embeddings):
    with open(feature_file,'w') as feaVecFile:
        for index,embed in enumerate(block_embeddings):
            feaVecFile.write(str(index)+" ")
            for k in embed:
                feaVecFile.write(str(k)+" ")
            feaVecFile.write("\n")
        '''
        for counter in block_embeddings:
            value = block_embeddings[counter]
            feaVecFile.write(str(counter) + " ")
            for k in range(len(value)):
                feaVecFile.write(str(value[k]) + " ")
            feaVecFile.write("\n")
        '''


def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    parser.add_argument('--input2', required=True, help='Input bin file 2')
    parser.add_argument('--outputDir', required=True, help='Specify the output directory') 
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    outputDir = args.outputDir

    if outputDir:
        config.file.update(outputDir)
    else:
        tdir = tempfile.mkdtemp()
        config.file.update(tdir)

    dbdlogger = logging.getLogger(config.logger_name)

    dbdlogger.info(f'outputdir:{config.file.output}')

    blockinfo_list, insnToBlockCounts, toBeMergedBlocks = preprocessing.preprocessing(filepath1, filepath2, outputDir)
 
    # 是否要考虑词频排序
    dictionary: Dictionary = genDictionary(blockinfo_list)

    walks = deepwalk.process(config.file.edgelist_file)
    
    article = Article(walks,blockinfo_list,dictionary)
    print(len(article.insns))
    exit()

    tokenEmbeddings = featureGen.generate_token_embeddings(article,len(dictionary))

    block_embeddings = cal_block_embeddings(blockinfo_list, insnToBlockCounts, tokenEmbeddings, dictionary)
    feature_vec_file_gen(config.file.features_file, block_embeddings) 

    # 检查返回值
    # !!python3
    tadw_command = "python ./src/performTADW.py --method tadw --input " + config.file.edgelist_file + " --graph-format edgelist --feature-file " + config.file.features_file + " --output "+config.file.embedding_file
    os.system(tadw_command)

    matching_driver.pre_matching(config.file.embedding_file,config.file.node_file, toBeMergedBlocks)

# 生成文章，生成batch数据
class Article:
    def __init__(self,walks, blockinfos, dictonary):
        self.data_index = 4
        self.insn_index = 1
        self.article, self.insns = articlesGen(walks,blockinfos,dictonary)
        self.limit = len(self.insns)-3

    # (context(2,5),target)
    def one(self):
        context = [[0 for _ in range(4)] for _ in range(2)]
        iid = self.insn_index

        for i,token in enumerate(self.article[self.insns[iid-1]:self.insns[iid]]):
            assert i<4
            context[0][i]=token
        for i,token in enumerate(self.article[self.insns[iid+1]:self.insns[iid+2]]):
            assert i<4
            context[1][i]=token
        res=(context,self.article[self.data_index])

        self.data_index+=1
        if self.data_index == self.insns[iid+1]:
            self.insn_index+=1
        
        if self.insn_index > self.limit:
            self.insn_index=1
            self.data_index=4
        
        return res
    
    # ([context(2,5)],[target])
    def batch(self, num):
        context = []
        target = []
        for _ in range(num):
            a,b=self.one()
            context.append(a)
            target.append(b)
        return (context,target)

    def generate_batch_to_file(self):
        batches = []
        for i in range(100):
            batches.append(self.batch(config.batch_size))
        fp = open('batches.txt','w')
        json.dump(batches,fp)
        fp.close()

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
    # print(len(stmts))
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

def main2():
    parse = ArgumentParser()
    parse.add_argument('input1')
    parse.add_argument('input2')
    parse.add_argument('-o','--output')

    args = parse.parse_args()
    inputs = [args.input1, args.input2]

    # angr生成的cfg 中有 node 和 edgelist
    # 我们要给node 编号 方便生成随机游走 
    # 一定要从0开始编号吗 id hash ？ 或者不编号?
    # block信息
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
    # none block
    # 平坦化
    article = [node  for walk_ in walks for node in walk_]

    # 生成训练数据
    ctx_data, target_data = generateTrainData(article,dict_,vex_uniform)
    ctx_data = np.array(ctx_data)
    target_data = np.array(target_data)
    data = tf.data.Dataset.from_tensor_slices((ctx_data,target_data))
    # tokenembedding
    tokenEmbeddings = featureGen.generate_token_embeddings2(data,len(vocab))

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
    main2()
