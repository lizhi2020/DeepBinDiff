import json
from typing import Dict, List
import angr
import os
import ntpath
import config

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

def get_external_functions(cfg,binary_name):
    externalSet = set() # 引用外部函数
    for func in cfg.functions.values():
        if not func.binary_name == binary_name:
            externalSet.add(func.name)
    return externalSet

def get_merge_nodes(cfgs,bin_names,node_dicts:List[Dict]):
    func_sets=[get_external_functions(cfgs[i],bin_names[i]) for i in range(2)]
    same_funcs = func_sets[0] & func_sets[1]
    print(same_funcs)
    nodeids = [{},{}]
    for i in range(2):
        for func in cfgs[i].functions.values():
            binName = func.binary_name
            funcName = func.name
            funcAddr = func.addr
            blockList = list(func.blocks)
            if (binName == bin_names[i]) and (funcName in same_funcs) and (len(blockList) == 1):
                for node,id in node_dicts[i].items():
                    if node.block and (node.block.addr == funcAddr):     
                        nodeids[i][funcName]=id
    
    # 两个bin的调用的外部函数的数量未必相等且小于全部的外部函数
    common_funcs = nodeids[0].keys() & nodeids[1].keys()
    return dict((nodeids[0][func],nodeids[1][func]) for func in common_funcs)

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
            print(binName,funcName)
            exit()
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

    config.dbdlogger.debug(f"TOBEMEGERED size: {len(toBeMergedBlocks)} | {toBeMergedBlocks}")
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
    # substitude offset with strings
    elif opstrNum in offsetStrMapping:
        optoken = offsetStrMapping[opstrNum]
    elif opstr.startswith("0x") or opstr.startswith("-0x") or opstr.replace('.','',1).replace('-','',1).isdigit():
        optoken = 'imme'
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
    return optoken

# 这里写 output/edgelist
# This function generates super CFG edge list. We also replace external function blocks in binary 2 from block in binary 1
def edgeListGen(cfgs, node_dicts, dst: str):
    with open(dst, 'w') as edgelistFile:
        for cfg,node_dict in zip(cfgs,node_dicts):
            for (src, tgt) in cfg.graph.edges:
                edgelistFile.write(str(node_dict[src]) + " " + str(node_dict[tgt]) + "\n")

# 输出 output/nodeIndexToCode 文件
def writeNodeFile(nodelist1:List,nodelist2:List,dst):
    with open(dst,'w') as file:
        file.write(str(len(nodelist1))+" "+str(len(nodelist2))+"\n")
        for index,node in enumerate(nodelist1+nodelist2):
            if node.block:
                file.write(str(index)+':\n')
                file.write(str(node.block.capstone.insns)+'\n\n')

# preprocessing the two binaries with Angr. try to creat outputdir if it doesn't exist
def preprocessing(filepath1, filepath2, outputDir):
    binary1 = path_leaf(filepath1)
    binary2 = path_leaf(filepath2)

    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    cfg1 = getCFG(filepath1)
    cfg2 = getCFG(filepath2)

    nodelist1 = list(cfg1.graph.nodes)
    edgelist1 = list(cfg1.graph.edges)

    nodelist2 = list(cfg2.graph.nodes)
    edgelist2 = list(cfg2.graph.edges)

    # 注意 nodeID与blockinf_list的索引是对应的。对一个node 其id为nodeID[node] 其blockinfo = blockinfo_list[id]
    # todo opt
    nodeID = GenNodeID([cfg1,cfg2])

    with open(config.file.node_file,'w') as fp:
        json.dump([len(nodelist1),len(nodelist2)],fp)
    # 相同的偏移包含不同的字符串？
    offstrmap, externFuncNamesBin1 = getOffsetStrMap(cfg1,binary1)
    tmpmap, externFuncNamesBin2 = getOffsetStrMap(cfg2,binary2)

    offstrmap.update(tmpmap)
    blockinf_list,insToBlockCounts,string_bid_list = processblock([cfg1,cfg2],offstrmap,nodeID)
    
    # string_bid: 字符串到块的映射 用于判断块融合
    # 字符串判断逻辑暂时被删除

    # string_bid
    toBeMergedBlocks, _ = externBlocksAndFuncsToBeMerged(cfg1, cfg2, nodelist1, nodelist2, binary1, binary2, nodeID, externFuncNamesBin1, externFuncNamesBin2)
    # string_bid block merge

    # 这一步是必须的 deepwalk会读取该文件
    config.dbdlogger.info("generating CFGs")
    edgeListGen(edgelist1, edgelist2, nodeID, config.file.edgelist_file)

    config.dbdlogger.info("Preprocessing all done. Enjoy!!")
    return blockinf_list, insToBlockCounts, toBeMergedBlocks

def preprocessing2(filepath1, filepath2):
    binary1 = path_leaf(filepath1)
    binary2 = path_leaf(filepath2)

    cfg1 = getCFG(filepath1)
    cfg2 = getCFG(filepath2)

    nodelist1 = list(cfg1.graph.nodes)
    edgelist1 = list(cfg1.graph.edges)

    nodelist2 = list(cfg2.graph.nodes)
    edgelist2 = list(cfg2.graph.edges)

    # 注意 nodeID与blockinf_list的索引是对应的。对一个node 其id为nodeID[node] 其blockinfo = blockinfo_list[id]
    # todo opt
    nodeID = GenNodeID([cfg1,cfg2])
    # 生成邻居信息
    # processblock([cfg1,cfg2],offstrmap,nodeID)

    # 相同的偏移包含不同的字符串？
    offstrmap, externFuncNamesBin1 = getOffsetStrMap(cfg1,binary1)
    tmpmap, externFuncNamesBin2 = getOffsetStrMap(cfg2,binary2)

    offstrmap.update(tmpmap)
    
    # string_bid: 字符串到块的映射 用于判断块融合
    # 字符串判断逻辑暂时被删除

    # string_bid
    toBeMergedBlocks, _ = externBlocksAndFuncsToBeMerged(cfg1, cfg2, nodelist1, nodelist2, binary1, binary2, nodeID, externFuncNamesBin1, externFuncNamesBin2)
    # string_bid block merge

    edgeListGen(edgelist1, edgelist2, nodeID, config.file.edgelist_file)
    return toBeMergedBlocks

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