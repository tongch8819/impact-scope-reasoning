from collections import defaultdict
from sklearn.linear_model import LogisticRegression
import pickle
import numpy as np
import argparse, os
import multiprocessing
import breakPointResume


class Feature:
    def __init__(self,
                 graph_file="data/train.graph.r100vul.txt",
                 path_file="data/paths.threshold.txt",
                 save_file='data/train.txt', train_file=None, test_file=None):
        self.graph_file = graph_file
        self.path_file = path_file
        self.train_file = train_file
        self.test_file = test_file
        self.save_file = save_file
        self.nodes = {}  # 记录节点的关系信息
        self.relation_paths = []  # record path pattern info
        self.train_data = defaultdict(list)
        self.test_data = None
        self.test_prob = dict()

        self.__init_range()
        self.__init_relation_paths()
        with open(train_file, 'r') as rd:
            self.sample_data = rd.readlines()

    # private method, not callable
    def __init_range(self):  # 设置关系的值域和节点的关系信息
        with open(self.graph_file, "r") as f:
            for data in f.readlines():
                node_1, relation, node_2 = data.strip().split("\t")
                if node_1 not in self.nodes.keys():
                    tem_node = Node(node_1)
                    self.nodes[node_1] = tem_node
                self.nodes[node_1].add(relation, node_2)

    # private method, not callable
    def __init_relation_paths(self):
        with open(self.path_file, "r") as f:
            paths = f.readlines()
            for path in paths:
                self.relation_paths.append(path.strip().split("\t")[1:])



    def _prob(self, begin, end, relation_path, last_node=None):  # 采取后向截断的动态规划
        prob = 0.0
        length = len(relation_path)
        if length == 1:
            if end in self.nodes[begin].info[relation_path[0]]:
                prob = 1 / len(self.nodes[begin].info[relation_path[0]])
            else:
                prob = 0.0
            return prob
        else:
            # if self.nodes[begin].info[relation_path[0]] == []:
            if len(self.nodes[begin].info[relation_path[0]]) == 0:
                return 0.0
            else:
                for entity in self.nodes[begin].info[relation_path[0]]:
                    if entity != last_node:
                        prob += (1 / len(self.nodes[begin].info[relation_path[0]])) * self._prob(entity, end,
                                                                                                 relation_path[1:], last_node=begin)
                return prob

    def _prob_with_end_type(self, begin, end_type, relation_path, last_node=None):  # 采取后向截断的动态规划
        res = defaultdict(lambda: 0.)
        length = len(relation_path)
        if length == 1:
            for node in self.nodes[begin].info[relation_path[0]]:
                if node.split('$')[0] == end_type:
                    prob = 1 / len(self.nodes[begin].info[relation_path[0]])
                    res[node] = prob
            return res
        else:
            if self.nodes[begin].info[relation_path[0]] == []:
                return res
            else:
                for entity in self.nodes[begin].info[relation_path[0]]:
                    if entity != last_node:
                        next_res = self._prob_with_end_type(entity, end_type, relation_path[1:], last_node=begin)
                        for key, value in next_res.items():
                            res[key] += (1 / len(self.nodes[begin].info[relation_path[0]])) * value
                return res

    def _walkers_prob(self, walker_num, begin, end, relation_path):  # Finger Print 方法是基于蒙特卡洛方法来估计路径概率
        walkers = []
        for n in range(walker_num):
            walkers.append(Walker("%d" % n, begin))
        for relation in relation_path:
            for walker in walkers:
                if walker.state == "walking":
                    start = walker.walk_history[-1]
                    subnodes = self.nodes[start].info[relation]
                    walker.onestep_walk(subnodes)
                else:
                    continue
        count = 0
        for walker in walkers:
            if walker.walk_history[-1] == end and walker.state == "walking":
                count += 1
        return count / walker_num

    def _particle_filtering_prob(self, walker_num, begin, end, relation_path, threshold_num=5):

        walkers = []
        for n in range(walker_num):
            walkers.append(Walker("%d" % n, begin))

        old_node_workers = {begin: walkers}

        for relation in relation_path:
            current_node_workers = defaultdict(list)
            for node in old_node_workers.keys():
                subnodes = self.nodes[node].info[relation]
                if subnodes == []:
                    continue
                else:
                    mean = len(old_node_workers[node]) / len(subnodes)
                    if mean >= threshold_num:  # 说明够分
                        num_distribute = int(mean)
                        k = 0
                        for subnode in subnodes:
                            if len(old_node_workers[node]) - k >= mean:
                                for l in range(num_distribute):
                                    current_node_workers[subnode].append(old_node_workers[node][k + l])
                                k += num_distribute
                            else:
                                for l in range(k, len(old_node_workers[node])):
                                    current_node_workers[subnode].append(old_node_workers[node][k + l])
                    else:  # 不够分，就按最小的分，但是是随机分
                        k = 0
                        for l in range(int(len(old_node_workers[node]) / threshold_num)):
                            ran = np.random.randint(len(subnodes), size=1)[0]
                            if len(old_node_workers[node]) - k >= threshold_num:
                                for n in range(threshold_num):
                                    current_node_workers[subnodes[ran]].append(old_node_workers[node][k + l])
                                k += threshold_num
                            else:
                                for l in range(k, len(old_node_workers[node])):
                                    current_node_workers[subnodes[ran]].append(old_node_workers[node][k + l])
            old_node_workers = current_node_workers

        if end in old_node_workers.keys():
            return len(old_node_workers[end]) / walker_num
        else:
            return 0

    def _neo4j_random_walk_prob(self):
        print("to be continued")

    def _low_sample_varaince(self):
        print("to be continued")

    def get_probs_train(self, prob_flag="pcrw-exact", walker_num=50, slice_obj=None, bpt=0):  # calculate path feature
        """
        bpt: break point
        """

        datas = self.sample_data[slice_obj] if slice_obj is not None else self.sample_data
        datas = datas[bpt:]  # breakpoint resume

        buffer = defaultdict(list)
        for s, data in enumerate(datas):
            if s % 500 == 0:
                print('current train data: ', s)

            # strip \n and ' ' explicitly
            [node_1, node_2] = data.strip("\n ")[0:-3].split(",")
            if node_1 not in self.nodes.keys():
                print("unregistered entity found: ", node_1)
                continue
            else:
                flag = data.strip()[-1]
                if flag == "+":
                    # given two entities, either positive or negative, so only the first one can be a label
                    self.train_data[(node_1, node_2)].append(1)
                else:
                    self.train_data[(node_1, node_2)].append(0)
                for path in self.relation_paths:
                    print('---------')
                    print("Current path: {}".format(path))
                    if prob_flag == "pcrw-exact":
                        tem = self._prob(node_1, node_2, path)
                    elif prob_flag == "finger-print":
                        tem = self._walkers_prob(walker_num=walker_num,
                                                 begin=node_1,
                                                 end=node_2,
                                                 relation_path=path)
                    elif prob_flag == "particle-filter":
                        tem = self._particle_filtering_prob(walker_num=walker_num,
                                                            begin=node_1,
                                                            end=node_2,
                                                            relation_path=path,
                                                            threshold_num=5)
                    else:
                        raise Exception('Error Flag.')
                    print('tem: {}  s: {}\n'.format(tem, s))
                    self.train_data[(node_1, node_2)].append(tem)
                    buffer[(node_1, node_2)].append(tem)
                # write every time a sample finished all path pattern
                with open(self.save_file + ".cumul.start" + str(slice_obj.start), "a+") as f:
                    for key, value in buffer.items():
                        f.write(str(key) + "\t" + str(value) + "\n")
                buffer.clear()

        # write total data
        with open(self.save_file, "w") as f:
            for key in self.train_data:
                f.write(str(key) + "\t" + str(self.train_data[key]) + "\n")
        return

    def get_probs_test(self, target_type, target_relation_type):  # calculate path feature
        """

        :param target_type: 推理的目标节点类型，例如CPE推理，target_type为CPE
        :param target_relation_type: 推理的目标关系类型，例如CPE推理，target_relation_type为Scope_Of_Influences
        :return:
        """
        self.test_data = defaultdict(lambda: [0]*len(self.relation_paths))

        f = open(self.test_file, "r")
        datas = f.readlines()
        f.close()

        assert self.save_file is not None

        with open(self.save_file, "w") as f:

            for s, data in enumerate(datas):
                if s % 10 == 0:
                    print('current test data: ', s)

                node_1 = data.strip()
                test_data_node_1 = defaultdict(lambda: [0] * len(self.relation_paths))
                if node_1 not in self.nodes.keys():
                    print("unregistered entity found: ", node_1)
                    continue
                else:
                    for i, path in enumerate(self.relation_paths):
                        tem = self._prob_with_end_type(node_1, target_type, path)
                        for node_2, prob in tem.items():
                            self.test_data[(node_1, node_2)][i] = prob
                            test_data_node_1[(node_1, node_2)][i] = prob

                for key in test_data_node_1.keys():
                    if key[1] not in self.nodes[key[0]].info[target_relation_type]:
                        f.write(str(key) + "\t" + str(test_data_node_1[key]) + "\n")

        return

    def get_probs_single(self, node_1, node_2, prob_flag="pcrw-exact", walker_num=50):
        probs = []
        for path in self.relation_paths:

            if prob_flag == "pcrw-exact":
                tem = self._prob(node_1, node_2, path)

            elif prob_flag == "finger-print":
                tem = self._walkers_prob(walker_num=walker_num,
                                         begin=node_1,
                                         end=node_2,
                                         relation_path=path)
            elif prob_flag == "particle-filter":
                tem = self._particle_filtering_prob(walker_num=walker_num,
                                                    begin=node_1,
                                                    end=node_2,
                                                    relation_path=path,
                                                    threshold_num=5)
            else:
                raise Exception('Error Flag.')

            probs.append(tem)
        return probs

    def func(self, a,b,c):
        print(a,b,c)


class Node:
    def __init__(self, NodeName):
        self.name = NodeName
        self.info = defaultdict(list)  # 记录从实体NodeName出发，经关系relation,能到达的实体

    def add(self, relation, subnode):
        self.info[relation].append(subnode)


class Walker:
    def __init__(self, name, begin):
        self.name = name
        self.walk_history = [begin]
        self.state = "walking"

    def onestep_walk(self, subnodes):
        if subnodes == []:
            self.state = "stop"
            # print("walker %s stopped!"%self.name)
            return
        else:
            n = len(subnodes)
            m = np.random.randint(n, size=1)[0]
            self.walk_history.append(subnodes[m])
        return



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    train_parser = subparsers.add_parser(
        'train', help='Generate feature used in training'
    )
    train_parser.add_argument('-g', '--graph_file', required=True, type=str, help="Path of graph file")
    train_parser.add_argument('-p', '--path_file', required=True, type=str, help="Path of path file")
    train_parser.add_argument('-s', '--save_path', required=True, type=str, help="Path to be saved")
    train_parser.add_argument('-t', '--train_file', required=True, type=str, help="Path of train file")
    train_parser.set_defaults(action='train')

    test_parser = subparsers.add_parser(
        'test', help='Generate feature used in testing'
    )
    test_parser.add_argument('-g', '--graph_file', required=True, type=str, help="Path of graph file")
    test_parser.add_argument('-p', '--path_file', required=True, type=str, help="Path of path file")
    test_parser.add_argument('-s', '--save_path', required=True, type=str, help="Path to be saved")
    test_parser.add_argument('-t', '--test_file', required=True, type=str, help="Path of train file")
    test_parser.add_argument('-m', '--model_file', default=None, type=str, help="Path of model file if filter by model prediction")
    test_parser.set_defaults(action='test')

    args = parser.parse_args()

    if args.action == 'train':
        feature = Feature(graph_file=args.graph_file, path_file=args.path_file, save_file=args.save_path,
                          train_file=args.train_file)
        # create 24 subprocesses
        process_num = 24
        pool = multiprocessing.Pool(processes=process_num)
        scale = len(feature.sample_data)
        batch_size = scale // process_num + 1
        start_lst = [x * batch_size for x in range(process_num)]

        # breakpoint resume

        # mapping = breakPointResume.buildMapping(directory=os.path.dirname(args.graph_file))
        # assert mapping is not None, "Build mapping failed"

        stop_lst = [min(x + batch_size, scale) for x in start_lst]
        for start, stop in zip(start_lst, stop_lst):
            pool.apply_async(
                feature.get_probs_train,
                # feature.func,
                # ("pcrw-exact", 50, slice(start, stop), mapping[start])
                ("pcrw-exact", 50, slice(start, stop))
            )
        pool.close()
        pool.join()


    elif args.action == 'test':
        feature = Feature(graph_file=args.graph_file, path_file=args.path_file, save_file=args.save_path,
                          test_file=args.test_file)
        feature.get_probs_test(target_type='CPE', target_relation_type='Scope_Of_Influences')

