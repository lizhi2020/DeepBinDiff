from typing import Dict, List
import angr
import os
import ntpath
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

# this list contains all the opcode in the two binaries
opcode_set = set()

# this dictionary stores the predecessors and successors of nodes
# per_block_neighbors_bids[block_id] = [[predecessors],[successors]]
per_block_neighbors_bids = {}

# blocks that have no code
non_code_block_ids = []

# register list
register_list_8_byte = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
register_list_4_byte = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'esp', 'ebp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
register_list_2_byte = ['ax', 'cx', 'dx', 'bx', 'si', 'di', 'sp', 'bp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
register_list_1_byte = ['al', 'cl', 'dl', 'bl', 'sil', 'dil', 'spl', 'bpl', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def angrGraphGen(filepath1, filepath2):
    prog1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    prog2 = angr.Project(filepath2, load_options={'auto_load_libs': False})

    print("Analyzing the binaries to generate CFGs...")
    cfg1 = prog1.analyses.CFGFast()
    cg1 = cfg1.functions.callgraph
    print("First binary done")
    cfg2 = prog2.analyses.CFGFast()
    cg2 = cfg2.functions.callgraph
    print("CFGs Generated!")

    nodelist1 = list(cfg1.graph.nodes)
    edgelist1 = list(cfg1.graph.edges)

    nodelist2 = list(cfg2.graph.nodes)
    edgelist2 = list(cfg2.graph.edges)
    return cfg1, cg1, nodelist1, edgelist1, cfg2, cg2, nodelist2, edgelist2

# 为节点分配id 从0开始
# 返回字典 node:id
def GenNodeID(cfgs: List[angr.analyses.CFG],start=0):
    cnt=start
    nodeID={}
    for cfg in cfgs:
        for node in cfg.graph.nodes:
            nodeID[node] = cnt
            cnt+=1
    return nodeID

def getOffsetStrMap(cfg,binary_name):
    mapping = {} # 偏移:字符串
    externalSet = set() # 引用外部函数
    for func in cfg.functions.values():
        if func.binary_name == binary_name:
            for offset, strRef in func.string_references(vex_only=True):
                mapping[str(offset)] = ''.join(strRef.split()) # why str() why split
        else:
            externalSet.add(func.name)
    return (mapping,externalSet)
# This func extracts the blocks that represent the same external function from both binary 1 and 2. 
# For example, from libc.so
# Somehow angr will create a block in binary 1 and 2 if they call an external function
def externBlocksAndFuncsToBeMerged(cfg1, cfg2, nodelist1, nodelist2, binary1, binary2, nodeID: Dict, externFuncNamesBin1, externFuncNamesBin2):
    # toBeMerged[node1_id] = node2_id
    toBeMergedBlocks = {}
    toBeMergedBlocksReverse = {}

    # toBeMergedFuncs[func1_addr] = func2_addr
    toBeMergedFuncs = {}
    toBeMergedFuncsReverse = {}
    
    externFuncNameBlockMappingBin1 = {}
    externFuncNameBlockMappingBin2 = {}
    funcNameAddrMappingBin1 = {}
    funcNameAddrMappingBin2 = {}

    for func in cfg1.functions.values():
        binName = func.binary_name
        funcName = func.name
        funcAddr = func.addr
        blockList = list(func.blocks)
        # problem?
        if (binName == binary1) and (funcName in externFuncNamesBin1) and (len(blockList) == 1):
            for node in nodelist1:
                if (node.block is not None) and (node.block.addr == blockList[0].addr):     
                    externFuncNameBlockMappingBin1[funcName] = nodeID[node]
                    funcNameAddrMappingBin1[funcName] = funcAddr

    for func in cfg2.functions.values():
        binName = func.binary_name
        funcName = func.name
        funcAddr = func.addr
        blockList = list(func.blocks)
        if (binName == binary2) and (funcName in externFuncNamesBin2) and (len(blockList) == 1):
            for node in nodelist2:
                if (node.block is not None) and (node.block.addr == blockList[0].addr):     
                    externFuncNameBlockMappingBin2[funcName] = nodeID[node]
                    funcNameAddrMappingBin2[funcName] = funcAddr


    for funcName in externFuncNameBlockMappingBin1:
        if funcName in externFuncNameBlockMappingBin2:
            blockBin1 = externFuncNameBlockMappingBin1[funcName]
            blockBin2 = externFuncNameBlockMappingBin2[funcName]
            toBeMergedBlocks[blockBin1] = blockBin2
            toBeMergedBlocksReverse[blockBin2] = blockBin1
            
            func1Addr = funcNameAddrMappingBin1[funcName]
            func2Addr = funcNameAddrMappingBin2[funcName]
            toBeMergedFuncs[func1Addr] = func2Addr
            toBeMergedFuncsReverse[func2Addr] = func1Addr

    print("TOBEMEGERED size: ", len(toBeMergedBlocks),"\n", toBeMergedBlocks, "\n")
    return toBeMergedBlocks, toBeMergedBlocksReverse


# 归一化：只对操作数归一化
def normalization(opstr, offsetStrMapping):
    optoken = ''

    opstrNum = ""
    if opstr.startswith("0x") or opstr.startswith("0X"):
        opstrNum = str(int(opstr, 16))

    # normalize ptr
    if "ptr" in opstr:
        optoken = 'ptr'
        # nodeToIndex.write("ptr\n")
    # substitude offset with strings
    elif opstrNum in offsetStrMapping:
        optoken = offsetStrMapping[opstrNum]
        # nodeToIndex.write("str\n")
        # nodeToIndex.write(offsetStrMapping[opstr] + "\n")
    elif opstr.startswith("0x") or opstr.startswith("-0x") or opstr.replace('.','',1).replace('-','',1).isdigit():
        optoken = 'imme'
        # nodeToIndex.write("IMME\n")
    elif opstr in register_list_1_byte:
        optoken = 'reg1'
    elif opstr in register_list_2_byte:
        optoken = 'reg2'
    elif opstr in register_list_4_byte:
        optoken = 'reg4'
    elif opstr in register_list_8_byte:
        optoken = 'reg8'
    else:
        optoken = str(opstr)
        # nodeToIndex.write(opstr + "\n")
    return optoken

def functionIndexToCodeGen(cfg1, cg1, nodelist1, nodeDic1, cfg2, cg2, nodelist2, nodeDic2, binary1, binary2, outputDir):
    # store function addresses
    funclist1 = []
    funclist2 = []
    with open(outputDir + 'functionIndexToCode', 'w') as f:
        f.write(str(len(list(cg1.nodes))) + ' ' + str(len(list(cg2.nodes))) + '\n') # write #nodes in both binaries
        for idx, func in enumerate(list(cg1.nodes)):
            function = cfg1.functions.function(func)

            funclist1.append(function.addr)
            f.write(str(idx) + ':' + '\n')

            f.write('Bin1 ' + function.name + ' ' + hex(function.addr) + ' ' + function.binary_name + '\n')
            for block in function.blocks:
                for node in nodelist1:
                    if (node.block is not None) and (node.block.addr == block.addr):
                        f.write(str(nodeDic1[node]) + ' ')
            f.write('\n')

        for idx, func in enumerate(list(cg2.nodes)):
            function = cfg2.functions.function(func)

            funclist2.append(function.addr)
            f.write(str(idx+len(cg1.nodes)) + ':' + '\n')
            f.write('Bin2 ' + function.name + ' ' + hex(function.addr) + ' ' + function.binary_name +  '\n')
            for block in function.blocks:
                for node in nodelist2:
                    if (node.block is not None) and (node.block.addr == block.addr):
                        f.write(str(nodeDic2[node]) + ' ')
            f.write('\n')
    return funclist1, funclist2


# 这里写 output/edgelist
# This function generates super CFG edge list. We also replace external function blocks in binary 2 from block in binary 1
def edgeListGen(edgelist1, edgelist2, nodeID, toBeMergedReverse, outputDir):
    with open(outputDir + 'edgelist_merged_tadw', 'w') as edgelistFile:
        for (src, tgt) in edgelist1:
            edgelistFile.write(str(nodeID[src]) + " " + str(nodeID[tgt]) + "\n")
        for (src, tgt) in edgelist2:
            src_id = nodeID[src]
            tgt_id = nodeID[tgt]

            new_src_id = src_id
            new_tgt_id = tgt_id

            if src_id in toBeMergedReverse:
                new_src_id = toBeMergedReverse[src_id]
            if tgt_id in toBeMergedReverse:
                new_tgt_id = toBeMergedReverse[tgt_id]

            edgelistFile.write(str(new_src_id) + " " + str(new_tgt_id) + "\n")

    with open(outputDir + 'edgelist', 'w') as edgelistFile:
        for (src, tgt) in edgelist1:
            edgelistFile.write(str(nodeID[src]) + " " + str(nodeID[tgt]) + "\n")
        for (src, tgt) in edgelist2:
            edgelistFile.write(str(nodeID[src]) + " " + str(nodeID[tgt]) + "\n")


def funcedgeListGen(cg1, funclist1, cg2, funclist2, toBeMergedFuncsReverse, outputDir):
    with open(outputDir + 'func_edgelist', "w") as f:
        for edge in list(cg1.edges):
            f.write(str(funclist1.index(edge[0])) + ' ' + str(funclist1.index(edge[1])) + '\n')
        for edge in list(cg2.edges):
            src_addr = edge[0]
            tgt_addr = edge[1]

            src_id = funclist2.index(src_addr) + len(cg1.nodes)
            tgt_id = funclist2.index(tgt_addr) + len(cg1.nodes)

            new_src_id = src_id
            new_tgt_id = tgt_id

            if src_addr in toBeMergedFuncsReverse:
                new_src_id = funclist1.index(toBeMergedFuncsReverse[src_addr])
            if tgt_addr in toBeMergedFuncsReverse:
                new_tgt_id = funclist1.index(toBeMergedFuncsReverse[tgt_addr])

            f.write(str(new_src_id) + ' ' + str(new_tgt_id) + '\n')


# not used. we now generate node features from asm2vec
def nodeFeaturesGen(nodelist1, nodelist2, mneList, mneDic, constDic, offsetStrMapping, outputDir):
    # generate feature vector file for the two input binaries
    with open(outputDir + 'features','w') as feaVecFile:
        for i in range(len(nodelist1)):
            node = nodelist1[i]
            feaVec = []
            for _ in range(len(mneList) + len(offsetStrMapping)):
                feaVec.append(0)
            if node.block is not None:
                for const in node.block.vex.constants:
                    if str(const) != 'nan':
                        offset = str(const.value)#hex(int(const.value))
                    if offset in offsetStrMapping:
                        c = offsetStrMapping.get(offset)
                        pos = constDic[c]
                        feaVec[pos] += 1

                for insn in node.block.capstone.insns:
                    mne = insn.mnemonic
                    pos = mneDic[mne]
                    feaVec[pos] += 1

            # index as the first element and then output all the features
            feaVecFile.write(str(i) + " ")
            for k in range(len(feaVec)):
                feaVecFile.write(str(feaVec[k]) + " ")
            feaVecFile.write("\n")

        for i in range(len(nodelist2)):
            node = nodelist2[i]
            feaVec = []
            for x in range(len(mneList) + len(offsetStrMapping)):
                feaVec.append(0)
            if node.block is not None:
                for const in node.block.vex.constants:
                    if str(const) != 'nan':
                        offset = str(const.value)#hex(int(const.value))
                    if offset in offsetStrMapping:
                        c = offsetStrMapping.get(offset)
                        pos = constDic[c]
                        feaVec[pos] += 1
                        
                for insn in node.block.capstone.insns:
                    mne = insn.mnemonic
                    pos = mneDic[mne]
                    feaVec[pos] += 1
            j = i + len(nodelist1)
            feaVecFile.write(str(j) + " ")
            for k in range(len(feaVec)):
                feaVecFile.write(str(feaVec[k]) + " ")
            feaVecFile.write("\n")

# preprocessing the two binaries with Angr. try to creat outputdir if it doesn't exist
def preprocessing(filepath1, filepath2, outputDir):
    binary1 = path_leaf(filepath1)
    binary2 = path_leaf(filepath2)

    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    # cfg1, cg1, nodelist1, edgelist1, cfg2, cg2, nodelist2, edgelist2 = angrGraphGen(filepath1, filepath2)
    cfg1 = getCFG(filepath1)
    cfg2 = getCFG(filepath2)

    nodelist1 = list(cfg1.graph.nodes)
    edgelist1 = list(cfg1.graph.edges)

    nodelist2 = list(cfg2.graph.nodes)
    edgelist2 = list(cfg2.graph.edges)

    # 注意 nodeID与blockinf_list的索引是对应的。对一个node 其id为nodeID[node] 其blockinfo = blockinfo_list[id]
    # todo opt
    nodeID = GenNodeID([cfg1,cfg2])
    # 相同的偏移包含不同的字符串？
    offstrmap, externFuncNamesBin1 = getOffsetStrMap(cfg1,binary1)
    tmpmap, externFuncNamesBin2 = getOffsetStrMap(cfg2,binary2)

    offstrmap.update(tmpmap)
    blockinf_list,insToBlockCounts,string_bid_list = processblock([cfg1,cfg2],offstrmap,nodeID)
    
    # string_bid: 字符串到块的映射 用于判断块融合
    # 字符串判断逻辑暂时被删除

    # string_bid
    toBeMergedBlocks, toBeMergedBlocksReverse = externBlocksAndFuncsToBeMerged(cfg1, cfg2, nodelist1, nodelist2, binary1, binary2, nodeID, externFuncNamesBin1, externFuncNamesBin2)
    # string_bid block merge

    # 这一步是必须的 deepwalk会读取该文件
    print("\tgenerating CFGs...")
    edgeListGen(edgelist1, edgelist2, nodeID, toBeMergedBlocksReverse, outputDir)

    print("Preprocessing all done. Enjoy!!")
    return blockinf_list, insToBlockCounts, toBeMergedBlocks

# 返回cfg 该结构由angr提供
def getCFG(path):
    proj = angr.Project(path,load_options={'auto_load_libs':False})
    return proj.analyses.CFGFast()

def getMneSet(cfg):
    result = set()
    for node in cfg.graph.nodes:
        if node.block:
            for insn in node.block.capstone.insns:
                mne = insn.mnemonic
                result.add(mne)
    return result

class blockinfo():
    def __init__(self) -> None:
        self.tokens = [] # 统计词频计算权重 需要
        self.id = None # >=0 Bin1和Bin2的所有块的id不会重复
        self.total_insns = 0   # num of instructions
        self.opcodeCount = {} # opcode:num
# 处理统计块信息
# 返回 ( [blockinfo], insToBlockCounts)
# 处理 邻居信息
def processblock(cfgs: List[angr.analyses.cfg.cfg.CFG], offsetStrMapping, nodeID):
    blockinfo_list = []
    insToBlockCounts = {}
    str_bid_list = []
    for cfg in cfgs:
        str2bid = {}
        for node in cfg.graph.nodes:
            # extract predecessors and successors
            preds = [nodeID[i] for i in node.predecessors]
            succs = [nodeID[i] for i in node.successors]
            neighbors = [preds, succs]
            per_block_neighbors_bids[nodeID[node]] = neighbors
            # 处理块信息
            bi = blockinfo()
            bb: angr.block.Block = node.block
            opcode_count = {}
            if bb:
                # self.tokens有用吗 没有去重
                bi.total_insns = len(bb.capstone.insns)
                for insn in bb.capstone.insns:
                    opcode = insn.mnemonic
                    opcode_set.add(opcode) # 先记录这个opcode
                    if opcode not in opcode_count:
                        opcode_count[opcode] = 0
                        if opcode not in insToBlockCounts:
                            insToBlockCounts[opcode] = 0
                        insToBlockCounts[opcode] += 1
                        
                    opcode_count[opcode] += 1
                    # str(insn.mnemonic)?
                    bi.tokens.append(opcode)
                    opStrs = insn.op_str.split(", ")
                    for opstr in opStrs:
                        optoken = normalization(opstr, offsetStrMapping)
                    if optoken != '':
                        bi.tokens.append(optoken)

                    opstrNum = ""
                    if opstr.startswith("0x") or opstr.startswith("0X"):
                        opstrNum = str(int(opstr, 16))
                    if opstrNum in offsetStrMapping:
                        str2bid[offsetStrMapping[opstrNum]] = nodeID[node]

            bi.opcodeCount = opcode_count
            blockinfo_list.append(bi)
        str_bid_list.append(str2bid)

    return (blockinfo_list,insToBlockCounts,str2bid)