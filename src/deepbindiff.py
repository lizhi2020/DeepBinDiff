import json,config
import math, os, logging
import tempfile
from shutil import copyfile
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List

import matching_driver
import featureGen
import preprocessing
from deepwalk import deepwalk

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
    
    tokenEmbeddings = featureGen.generate_token_embeddings(article,len(dictionary))

    block_embeddings = cal_block_embeddings(blockinfo_list, insnToBlockCounts, tokenEmbeddings, dictionary)
    feature_vec_file_gen(config.file.features_file, block_embeddings) 

    matching_driver.pre_matching(toBeMergedBlocks)

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

if __name__ == "__main__":
    main()