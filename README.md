# Impact-Scope-Reasoning
This repository contains source code that uses data to reason the impact scope of the vulnerability with the data in VulGraph.

## to do list
+ set path limit to 3 and re-train the feature -- OK
+ json -> nvd_id -> (node_id, nvd_id) -- OK
+ refactor code to output multiplication of feature value and weight 

## Directory Structure
- graph_construction.py: generate subgraphs from Neo4j and store them as txt files.
- data_generation.py: generate positive and negative samples according to the graph txt file.
- DFS.py: get all possible paths between positive examples through DFS.
- feature.py: calculate the features of samples by random walk, thereby obtaining the feature vectors.
- model.py: train a logistic regression model based on the samples.
- reasioning.py: reasoning based on the trained model.



1. graph_construction.py：构造子图（Cypher）
2. data_generation.py：构造正例负例
3. DFS.py：搜索路经集合，确定维度
4. feature.py：求取特征值
5. model.py：训练逻辑回归分类器
6. reasioning.py：推理(base) 

### Pitfall
+ CPE name is not consistent between *train.pairs.txt* and *train.graph.txt*
    + one more ":" in *train.pairs.txt*


## Knowledge Graph

CPE: common product exposure
CWE: common weakness exposure

+ vulnerability -> cpe
+ vulnerability -> cwe
+ cpe -> vendor
+ cpe -> cpe
+ cwe -> cwe


## URL
+ [py2neo](https://py2neo.org/2020.0/)















## Usage
The 6 files in the directory structure need to be executed sequentially to realize the impact scope reasoning. The following is an example of reasoning the impact scope of IoT vulnerabilities.
#### generate subgraphs:
```bash
python graph_construction.py -s=data/train.graph.txt -c=物联网漏洞 -vl=xx
```
The limit number by `vl` parameter only applies to the demo stage. Do not use the `vl` parameter to limit the number of vulnerabilities during actual training.

#### generate samples:
```bash
python data_generation.py gen_train_sample -r=Scope_Of_Influences -g=data/train.graph.txt -s=data/train.pairs.txt
```

#### get all feature paths:
```bash
python DFS.py -s=data/paths.all.txt -fs=data/paths.threshold.txt -g=data/train.graph.txt -t=data/train.pairs.txt
```

#### calculate features
```bash
python feature.py train -g=data/train.graph.txt -t=data/train.pairs.txt -p=data/paths.threshold.txt -s=train.txt
```

#### train model
```bash
python model.py -s=data/model/ -f=data/train.txt -p=6
```

#### reasoning
1) generate test graph (If the graphs during training and testing are the same, this step can be omitted.)
```bash
python graph_construction.py -s=data/test.graph.txt -c=物联网漏洞
```
2) generate vulnerabilities to be test:
```bash
python data_generation.py gen_test_vul -s=data/test.vul.txt -c=物联网漏洞
```
3) start reasoning:
`feature` method:
```bash
python reasoning.py reasoning_all -gf=data/test.graph.txt -tf=data/test.vul.txt -pf=data/paths.threshold.txt -mf=data/model/model_1.pkl -sf=data/reasoning.result.txt -ff=data/test.txt -t=0.5 -m=model
```

`model` method:
```bash
python reasoning.py reasoning_all -gf=data/test.graph.txt -tf=data/test.vul.txt -pf=data/paths.threshold.txt -mf=data/model/model_1.pkl -sf=data/reasoning.result.txt -t=0.5 -m=model
```



## kernel exp 3
+ total: 2685, sample size 20
+ path_limit: 4
+ positive : negative = 1 : 10

### path pattern
1. vul -> cpe -> vul -> cpe
2. vul -> cpe -> vul -> cwe ??
3. vul -> cpe -> cpe -> cpe
4. vul -> cwe -> cwe -> cwe
5. cpe -> cpe -> cpe -> cpe
6. cpe -> cpe -> vul -> cpe
7. cpe -> vul -> cpe -> cpe
8. cwe -> cwe -> cwe -> cwe
9. vendor -> cpe -> cpe -> cpe
10. vendor -> cpe -> vul -> cpe







