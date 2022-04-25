from typing import Dict, List
import angr
import ntpath

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