# -*- coding: utf-8 -*-

from collections import defaultdict
from collections import Counter
import sys
import re

sys.setrecursionlimit(20000)


class graph:
    def __init__(self):

        self.nodes = {}  # 节点名字到(r,子节点)组构成的词典
        self.paths = []  # 记录所有搜索到的路径
        self.begin = ""
        self.path = defaultdict(list)  # 记录单条路径
        self.times = 0
        self.max_length = 5
        self.end = ""
        self.steps = 0
        self.relation_paths = []  # 记录所有关系路径，不包含实体

    def add(self, node, relation, next_node):
        if node in self.nodes:
            if next_node not in self.nodes:  # 需要先建立Node结构
                self.nodes[next_node] = Node(next_node)
            self.nodes[node].conjunctions.append((relation, self.nodes[next_node]))
        else:
            self.nodes[node] = Node(node)  # 创建头节点，然后依然调用此函数
            self.add(node, relation, next_node)

    def set_init(self, begin, end, max_length):  # 路径搜索时，初始化一些参数

        self.begin = begin
        self.end = end
        self.max_length = max_length
        self.path = [("root", self.begin)]
        self.paths = []
        self.relation_paths = []

    # self.max_times = max_search_times

    def dfs(self, begin, inv_relation=None):  # 深度优先搜索
        if begin == self.end:
            tem = []
            for n in self.path:
                tem.append(n)

            self.paths.append(tem)
            # print("paths",self.paths)
            return
        try:  # 偶尔出现没有在数据库中出现的实体，所以加一个try catch
            if self.nodes[begin].conjunctions is None:
                return
            if len(self.path) == self.max_length + 1:  # 设置一下最大路径长度
                return
            for (_relation, subnode) in self.nodes[begin].conjunctions:
                if (_relation, subnode.NodeName) not in self.path and (_relation, subnode.NodeName) != inv_relation:
                    self.path.append((_relation, subnode.NodeName))
                    self.dfs(subnode.NodeName, inv_relation=(direct_flip(_relation), begin))
                    # self.dfs(subnode.NodeName)
                    self.path.remove((_relation, subnode.NodeName))
        except:
            print("存在没有注册的实体%s\n" % begin)
        return

    def extract_route(self):  # 将路径中的关系单拿出来
        for path in self.paths:
            tem = ""
            for e in path:
                tem = tem + e[0] + "\t"
            self.relation_paths.append(tem)
        return


def direct_flip(rel):
    if re.search('_inv$', rel):
        return rel[:-4]
    else:
        return rel+'_inv'


class Node:
    def __init__(self, NodeName):
        self.NodeName = NodeName
        self.conjunctions = []


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--save_path', required=True, type=str, help="Path to be saved")
    parser.add_argument('-fs', '--filtered_save_path', required=True, type=str, help="Path of filtered paths to be saved")
    parser.add_argument('-g', '--graph_path', required=True, type=str, help="Path of the graph file")
    parser.add_argument('-t', '--train_path', required=True, type=str, help="Path of the train file")

    args = parser.parse_args()

    alpha = 0.01
    paths = []
    kg = graph()
    # path maximum length
    # max_length = 3
    max_length = 4

    with open(args.graph_path, "r") as f:
        datas = f.readlines()
        for data in datas:
            [node, relation, next_node] = data.strip().split("\t")
            # print(node)
            kg.add(node, relation, next_node)

    # add by Tong Cheng
    with open(args.save_path+".raw", "w") as f:
        f.write("Begin\n")
    timeout = 5

    with open(args.train_path, "r") as f:
        datas = f.readlines()
        for n, data in enumerate(datas):
            [node_1, node_2] = data.strip()[0:-3].split(",")
            flag = data.strip()[-1]
            if flag == "+":
                begin = node_1
                end = node_2
                kg.set_init(begin, end, max_length)
                print("开始第%d个样本对：\n" % n)
                kg.dfs(begin)  # 搜索begin和end之间的路径
                kg.extract_route()
                paths.extend(kg.relation_paths)
                # add by Tong Cheng
                print("Writing %d -th sample... \n" % n)
                with open(args.save_path+".raw", "a") as f:
                    for path in kg.relation_paths:
                        f.write(path + "\n")
            else:
                continue

    path_count = Counter(paths)
    with open(args.save_path, "w") as f:
        for path in path_count.keys():
            if path != 'root\tScope_Of_Influences\t':
                f.write(path + "%d" % path_count[path] + "\n")

    with open(args.save_path, "r") as f:
        dict = {}
        datas = f.readlines()
        for data in datas:
            path = data.strip().split("\t")[1:-1]
            num = int(data.strip().split("\t")[-1])
            path_str = ""
            for relation in path:
                path_str += (relation + "\t")
            dict[path_str] = num
        threshold = int(100 * alpha)
        dict_2 = {}
        for key in dict.keys():
            if dict[key] >= threshold:
                dict_2[key] = dict[key]
    with open(args.filtered_save_path, "w") as f:
        for n, key in enumerate(dict_2.keys()):
            f.write("%d\t" % n + key + "\n")
