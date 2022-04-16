import collections
import math

from shutil import copyfile
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List

import matching_driver
import featureGen
import preprocessing
from deepwalk import deepwalk


import tensorflow.compat.v1 as tf
tf.disable_v2_behavior()
import numpy as np

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
    article = []

    # stores all the block boundary indice. blockBoundaryIndices[i] is a list to store indices for articles[i].
    # each item stores the index for the last token in the block
    blockBoundaryIdx = []
    
    for walk in walks:
        # one random walk is served as one article
        for idx in walk:
            # idx should always <= len(blockinfo_list)
            tokens = blockinfo_list[int(idx)].tokens
            for token in tokens:
                article.append(dictionary.reverse_dictionary[token])
            blockBoundaryIdx.append(len(article) - 1)
            # aritcle.append(boundaryIdx)
        
    insnStartingIndices = []
    indexToCurrentInsnsStart = {}
    # blockEnd + 1 so that we can traverse to blockEnd
    # go through the current block to retrive instruction starting indices
    for i in range(len(article)): 
        if dictionary.tokens[int(article[i])] in preprocessing.opcode_set:
            insnStartingIndices.append(i)
        indexToCurrentInsnsStart[i] = len(insnStartingIndices) - 1
    return article, blockBoundaryIdx, insnStartingIndices, indexToCurrentInsnsStart


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
        # print("bid", bid, "block embedding:", block_embed)
    return block_embeddings


def feature_vec_file_gen(feature_file, block_embeddings):
    with open(feature_file,'w') as feaVecFile:
        for counter in block_embeddings:
            value = block_embeddings[counter]
            # index as the first element and then output all the features
            feaVecFile.write(str(counter) + " ")
            for k in range(len(value)):
                feaVecFile.write(str(value[k]) + " ")
            feaVecFile.write("\n")


def copyEverythingOver(src_dir, dst_dir):
    # ground_truth = 'addrMapping'
    node_features = 'features'
    cfg_edgelist = 'edgelist_merged_tadw'
    #func_edgelist = 'func_edgelist'
    #functionInfo = 'functionIndexToCode'
    nodeInfo = 'nodeIndexToCode'

    #copyfile('/home/yueduan/yueduan/groundTruthCollection/output/' + ground_truth, dst_dir + ground_truth)
    # copyfile(src_dir + ground_truth, dst_dir + ground_truth)
    copyfile(src_dir + node_features, dst_dir + node_features)
    copyfile(src_dir + cfg_edgelist, dst_dir + 'edgelist')
    #copyfile(src_dir + func_edgelist, dst_dir + func_edgelist)
    #copyfile(src_dir + functionInfo, dst_dir + functionInfo)
    copyfile(src_dir + nodeInfo, dst_dir + nodeInfo)

    #Yue: use feature as embedding
    # copyfile(src_dir + node_features, 'vec_all')

def main():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    parser.add_argument('--input2', required=True, help='Input bin file 2')
    parser.add_argument('--outputDir', required=True, help='Specify the output directory') 
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    outputDir = args.outputDir

    if outputDir.endswith('/') is False:
        outputDir = outputDir + '/'

    EDGELIST_FILE = outputDir + "edgelist"

    # 第一步 预处理
    # step 1: perform preprocessing for the two binaries
    # blockIdxToTokens, blockIdxToOpcodeNum, blockIdxToOpcodeCounts, insToBlockCounts, toBeMergedBlocks =\
    blockinfo_list, insnToBlockCounts, toBeMergedBlocks = preprocessing.preprocessing(filepath1, filepath2, outputDir)
    
    # 第二部 词汇表构建
    #step 2: vocabulary buildup
    # blockIdxToTokens 块对应的Token列表 binary1 binar2的块混在一起 
    dictionary: Dictionary = genDictionary(blockinfo_list)
    
    # 第三步 生成随机游走 每个随机游走包含特定的块
    # step 3: generate random walks, each walk contains certain blocks
    walks = deepwalk.process(EDGELIST_FILE)
    
    # 第4步 基于随机游走生成文章
    # step 4: generate articles based on random walks
    article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart = articlesGen(walks, blockinfo_list, dictionary)

    # 调用tf
    # step 5: token embedding generation
    tokenEmbeddings = featureGen.tokenEmbeddingGeneration(article, blockBoundaryIndex, insnStartingIndices, indexToCurrentInsnsStart, dictionary)
    
    # step 6: calculate feature vector for blocks
    block_embeddings = cal_block_embeddings(blockinfo_list, insnToBlockCounts, tokenEmbeddings, dictionary)
    feature_vec_file_gen(outputDir + 'features', block_embeddings) 

    copyEverythingOver(outputDir, 'data/DeepBD/')

    bin1_name = preprocessing.path_leaf(filepath1)
    bin2_name = preprocessing.path_leaf(filepath2)
    # step 7: TADW for block embedding generation & block matching
    matching_driver.pre_matching(bin1_name, bin2_name, toBeMergedBlocks)


if __name__ == "__main__":
    main()