import copy, os

class Node:
    def __init__(self, index, name):
        self.index = index
        self.name = name
        # maybe not useful
        # self.in_neighbors = []
        self.out_neighbors = []  # Edge container

    def __repr__(self):
        rst = "{}: ".format(self.name)
        for neighbor in self.out_neighbors:
            rst += "{}->".format(neighbor.name)
        return rst + "\n"

class Edge:
    def __init__(self, head_index, tail_index, name):
        self.head_index = head_index
        self.tail_index = tail_index
        self.name = name

    def __repr__(self):
        return "{} ---{}---> {}\n".format(self.head_index, self.name, self.tail_index)

class Digraph:
    def __init__(self):
        self.node_num = 0
        self.edge_num = 0
        self.node_lst = []  # index ascending
        self.edge_lst = []

    def __repr__(self):
        rst = "Node num: {}\n".format(self.node_num)
        rst += "Edge num: {}\n".format(self.edge_num)
        rst += "Adjacent list: \n"
        for node in self.node_lst:
            rst += str(node)
        rst += "\nEdge set: \n"
        for edge in self.edge_lst:
            rst += str(edge)
        return rst


    def __getitem__(self, item):
        """
        return Node object using index(item)
        """
        left = 0
        right = len(self.node_lst) - 1
        while left < right - 1:
            mid = (left + right) // 2
            if item < self.node_lst[mid].index:
                right = mid
            elif item > self.node_lst[mid].index:
                left = mid
            else:
                return self.node_lst[mid]
        if item == self.node_lst[left].index:
            return self.node_lst[left]
        if item == self.node_lst[right].index:
            return self.node_lst[right]
        return None

    def getEdge(self, head_index, tail_index):
        for edge in self.edge_lst:
            if edge.head_index == head_index and edge.tail_index == tail_index:
                return edge
        return None

    def add_node(self, index, options):
        self.node_lst.append( Node(index, options["name"]) )
        self.node_num += 1
        self.node_lst.sort(key=lambda x: x.index, reverse=False)  # ascending

    def add_nodes_from(self, container):
        for index, options in container:
            self.add_node(index, options)

    def add_edge(self, head_index, tail_index, name="Unknown"):
        if self[head_index] is not None and self[tail_index] is not None:
            self[head_index].out_neighbors.append(self[tail_index])
            # add bi-directional edges
            self.edge_lst.append( Edge(head_index, tail_index, name) )
            self.edge_num += 1
            if head_index != tail_index:
                # loop has no inverse
                self.edge_lst.append(Edge(tail_index, head_index, name + "_inv"))
                self[tail_index].out_neighbors.append(self[head_index])
                self.edge_num += 1


    def add_edges_from(self, container):
        for head, tail, name in container:
            self.add_edge(head, tail, name)

    def dfs(self):
        pass

    def bfs(self):
        pass

    def findPath(self, head_index, length):
        if length == 0: return [[head_index]]
        head = self[head_index]
        # if head is None: return None
        rst = []
        for out_neighbor in head.out_neighbors:
            res = self.findPath(head_index=out_neighbor.index, length=length - 1)
            rst += [[head_index] + x for x in res]
        return rst

    def indexsToNodeNames(self, container):
        return [self[x].name for x in container]

    def indexsToEdgeNames(self, container):
        """
        transform a path like [1,2,2] into 2 edge names tuple
        return list of edge tuple
        """
        if len(container) < 2:
            return []
        rst = []
        for i in range(len(container) - 1):
            if container[i] == container[i+1]:
                result = self.indexsToEdgeNames(container=container[i+1:])
                if len(rst) > 0:
                    right = copy.deepcopy(rst)
                    for x in rst:
                        x.append(self.getEdge(container[i], container[i + 1]).name)
                    for y in right:
                        y.append(self.getEdge(container[i], container[i + 1]).name+"_inv")
                    rst.extend(right)
                    del right
                else:
                    tmp_name = self.getEdge(container[i], container[i + 1]).name
                    rst= [ [tmp_name], [tmp_name + "_inv"] ]
                # left = [x.append(self.getEdge(container[i], container[i+1]).name) for x in rst]
                # right = [x.append(self.getEdge(container[i], container[i + 1]).name+"_inv") for x in rst]
                # rst = left + right
                if len(result) > 0:
                    rst = [x+y for x in rst for y in result]
                return rst  # stop early
            else:
                if len(rst) == 0:
                    rst = [[self.getEdge(container[i], container[i+1]).name]]
                else:
                    [x.append(self.getEdge(container[i], container[i+1]).name) for x in rst]
        return rst
        # return [self.getEdge(container[i], container[i+1]).name for i in range(len(container)-1)]



def kernelExpRawPathPattern():
    dg = Digraph()
    dg.add_nodes_from([
        (1, {"name": "VUL"}),
        (2, {"name": "CPE"}),
        (3, {"name": "CWE"}),
        (4, {"name": "Vendor"}),
        # (5, {"name": "TongCheng"})
    ])
    dg.add_edges_from([
        (1, 2, "Scope_Of_Influences"),
        (1, 3, "CausedBy"),
        (2, 2, "BasedOn"),
        (3, 3, "ChildOf"),
        (4, 2, "Develop")
        # (1, 1, "Hello"),
        # (1, 5, "Bother")
    ])
    print(dg)

    raw = []
    for i in range(1,5):
        for j in range(2,5):
            raw.extend( dg.findPath(i, j))
    rst = [x for x in raw if (x[-1] == 2 and x[0] == 1)]
    # rst = [x for x in raw]
    # with open("kernel-exp/abstract_paths.txt", "w") as wrt_fd:
    #     wrt_fd.writelines([",".join([str(y) for y in x])+"\n" for x in rst])
    # rst_names = [dg.indexsToEdgeNames(v) for v in rst]
    rst_names = []
    for v in rst:
        rst_names.extend(dg.indexsToEdgeNames(v))
    for ele in rst_names:
        print(ele)
    print("\n Dimension: {}".format(len(rst_names)))
    # with open("kernel-exp/abstract_paths.txt", "w") as wrt_fd:
    #     lines = []
    #     for i in range(len(rst_names)):
    #         lines.append(str(i) + "\t" + " ".join(rst_names[i]))
    #     wrt_fd.write("\n".join(lines))
    return rst_names


def writePathPattern(container, path):
    with open(path, "w") as wrt_fd:
        lines = []
        for i in range(len(container)):
            lines.append(str(i) + "\t" + "\t".join(container[i]))
        wrt_fd.write("\n".join(lines))

def parsePositiveSample(path):
    with open(path, 'r') as rd_fd:
        content = rd_fd.readlines()
    rst = []
    for line in content:
        if line[-2] == '+':
            rst.append( line.split(" ")[0].split(",") )
        else:
            break
    return rst

from feature import Feature
def pathPatternFiltering(graph_path, raw_pattern_path, pairs_path):
    f = Feature(graph_file=graph_path, path_file=raw_pattern_path)

    def relationReverse(relation):
        if relation[-4:] == "_inv":
            return relation[:-4]
        else:
            return relation + "_inv"

    def func(obj, begin, end, relation_path, last_node=None):  # 采取后向截断的动态规划
        if len(relation_path) == 1:
            return True if end in obj.nodes[begin].info[relation_path[0]] else False
        else:
            if len(obj.nodes[end].info[relationReverse(relation_path[-1])]) == 0:
                return False
            if len(obj.nodes[begin].info[relation_path[0]]) == 0:
                return False

            for entity in obj.nodes[begin].info[relation_path[0]]:
                if entity != last_node and func(obj, entity, end, relation_path[1:], begin):
                    return True
            return False

    def positiveTune(name):
        return name[:-1] if name[:3] == "CPE" else name

    rst = []
    # generate positive name set
    head_tail_lst = parsePositiveSample(pairs_path)

    os.system("touch kernel-exp/abstract_paths.txt.filtered.backup")
    print("Scale: {}\n".format(len(head_tail_lst)))
    for k, cur_path in enumerate(f.relation_paths):
        # cur_path = cur_path[0].split(" ")
        # mark = False
        print("{}-th path: {}".format(k, cur_path))
        for i, (head, tail) in enumerate(head_tail_lst):
            progress = int(i / len(head_tail_lst) * 100)
            print("\r" + "-" * progress + "{}%".format(progress), end="")

            if func(f, positiveTune(head), positiveTune(tail), cur_path):
                rst.append(cur_path)
                os.system("echo '" + str(cur_path) + "' >> kernel-exp/abstract_paths.txt.filtered.backup")
                print("\nMatch. Length of result: {}".format(len(rst)), end="")
                break
        print()


    return rst



def main():
    # generate abstract path pattern
    # rst = kernelExpRawPathPattern()
    # writePathPattern(rst, "kernel-exp/abstract_paths.txt")

    # filter abstract path pattern
    rst = pathPatternFiltering(
        graph_path="./kernel-exp/train.graph.txt",
        raw_pattern_path="./kernel-exp/abstract_paths.txt",
        pairs_path="./kernel-exp/train.pairs.txt"
    )
    print(len(rst))
    writePathPattern(rst, "kernel-exp/abstract_paths.txt.filtered")

    # rst = parsePositiveSample("kernel-exp/train.pairs.txt")
    # for ele in rst:
    #     a,b = ele
    #     print(a,b)
    #     break



if __name__ == "__main__":
    main()
