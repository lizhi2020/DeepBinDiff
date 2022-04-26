*这不是DeepBindDiff的官方仓库，本仓库在原仓库的基础上进行改进和优化*

# How to run

```
python3 src/deepbindiff.py path_to_the_first_binary path_to_the_second_binary -o outputdir
```

# example
* For example, to compare O0 and O1 chroot binaries from coreutils v5.93, you may run:

```
python3 src/deepbindiff.py ./experiment_data/coreutils/binaries/coreutils-5.93-O0/chroot ./experiment_data/coreutils/binaries/coreutils-5.93-O1/chroot -o output/
```
在该例子中，bin1应当有617个节点`node`,bin2有563个节点。注意并不是所有的节点`node`都有实际的代码块`block`的。

比如`call rax`会为当前节点添加一个后继节点`<CFGNode UnresolvableCallTarget [0]>`,因为无法通过静态的方式确定跳转地址，所以该节点是空的，即`node.block == None`。

大部分情况下，`node`等价于`block`。

目前对`token`和`node`都采用了连续整数编码（从0开始），前者是为了便于`embedding lookup`，后者是为了方便tadw和匹配算法

起始的匹配对是通过查找相同的外部函数调用来完成的。比如`bin1`调用了属于`libc.so`的`getenv`函数，那么在`angr`的分析结果中会存在两个`name == 'getenv'`的函数，其`binary_name`属性分别为`'bin1'`和`'libc.so'`

# 组件

预处理: tobemerged_block edgelist nodes node_dict vocab vocab_dict

嵌入生成: tokemembedding blockembeding

tadw

匹配


# DeepBinDiff

This is the official repository for DeepBinDiff, which is a fine-grained binary diffing tool for x86 binaries. We will actively update it.

### Paper
Please consider citing our paper.

Yue Duan, Xuezixiang Li, Jinghan Wang, and Heng Yin, "DeepBinDiff: Learning Program-Wide Code Representations for Binary Diffing", NDSS'2020


### Requirements:
详见requirements.txt

安装依赖`pip install -r requirements.txt`


### Misc
1. IDA Pro or Angr?

We have both the IDA pro version and the angr version. IDA pro is used in order to directly compare with BinDiff, which uses IDA pro as well. The code here uses Angr.

2. Results?

Results are printed directly on the screen as "matched pairs" once the diffing is done. Each pair represents a matched pair of basic blocks in the two binaries. The numbers are the basic block indices, which can be found in output/nodeIndexToCode file.

3. CPU or GPU?

The current version is using CPU only. 

4. NLP pre-training?

The current version uses an on-the-fly training process, meaning we only use the two input binaries for NLP training. Therefore, we don't need any pre-trained model. This will eliminate the OOV problem but will slow down the process a bit.
