import argparse, sys
from collections import defaultdict
from sklearn.linear_model import LogisticRegression
from math import exp
import numpy as np
import pickle

sys.path.append('./')
from feature import Feature, Node
from timer import set_timeout

class Reasoner:
    def __init__(self, graph_file="data/test.graph.txt", model_file="data/model_1.pkl",
                 path_file="data/paths.threshold.txt", test_file="data/test.vul.txt",
                 feature_file="data/test.txt", save_file='data/reasoning.result.txt',
                 weight_file="data/path.weights.1.txt", threshold=0.55):
        # input file path
        self.graph_file = graph_file
        self.model_file = model_file
        self.path_file = path_file  # path pattern
        self.test_file = test_file  # test vulnerability set
        self.save_file = save_file
        self.weight_file = weight_file
        self.feature_file = feature_file
        # inner container
        self.path_weights = list()
        self.path_length = list()
        self.model = None
        self.features = defaultdict(list)
        self.threshold = threshold
        self.g_param = [1, 0, 1]  # Gaussian parameters
        self.feature_calculator = Feature(graph_file=self.graph_file, path_file=self.path_file,
                                          test_file=None, save_file=None)
        self.__init_model()

    # private method
    def __init_model(self):
        """
        加载训练完毕的sklearn的LogisticRegression模型
        :return:
        """
        with open(self.model_file, 'rb') as f:
            self.model = pickle.load(f)

    def init_path_weights(self):
        """
        初始化路径权重，在不使用sklearn的LogisticRegression预测时使用
        :return:
        """
        with open(self.weight_file, 'r') as f:
            data = f.readlines()
        for d in data:
            [path_id, weight] = d.strip().split('\t')
            self.path_weights.append(float(weight))

    def init_path_length(self):
        """
        初始化路径长度，在不使用sklearn的LogisticRegression预测，并且使用高斯函数根据路径长度对权重进行校正时使用
        :return:
        """
        with open(self.path_file, 'r') as f:
            data = f.readlines()
        for d in data:
            path = d.strip().split('\t')[1:]
            self.path_length.append(len(path))

    def gaussian(self, x):
        return self.g_param[0] * exp(-(x - self.g_param[1]) ** 2 / 2 * self.g_param[2] ** 2)

    def calculate_score(self, feature, use_gaussian=False):
        """
        手动根据路径权重计算分数，目前废弃。如果使用，需加上截距项，参考vulgraph-web。
        :param feature:
        :param use_gaussian:
        :return:
        """
        print('-- self.path_length --: ', self.path_length, ' type: ', type(self.path_length))
        print('-- np.array(feature) --: ', np.array(feature), ' type: ', type(np.array(feature)))
        print('-- np.array(self.path_weights) --: ', np.array(self.path_weights), ' type: ', type(np.array(self.path_weights)))
        ele_wise_product = np.array(feature) * np.array(self.path_weights)
        if use_gaussian:
            ele_wise_product *= self.path_length
        score = np.sum(ele_wise_product)
        return float(score)

    def reasoning_all_manually(self):
        """
        已废弃
        :return:
        """
        results = defaultdict(list)
        self.features = self.feature_calculator.get_probs_test(prob_flag="pcrw-exact")
        for key in self.features:
            score = self.calculate_score(feature=self.features[key])
            results[key] = [score, 1 if score >= self.threshold else 0]

        with open(self.save_file, 'w') as f:
            for key in results.keys():
                if results[key][1] == 1:
                    f.write(str(key) + "\t" + str(results[key][0]) + "\t" + str(results[key][1]) + "\n")

    def reasoning_all_by_model(self, target_type, target_relation_type):
        """
        :param target_type: 推理的目标节点类型，例如CPE推理，target_type为CPE
        :param target_relation_type: 推理的目标关系类型，例如CPE推理，target_relation_type为Scope_Of_Influences
        :return:
        """
        f = open(self.test_file, "r")
        datas = f.readlines()
        f.close()

        timeout = 60
        def after_timeout():
            return None
        @set_timeout(timeout, after_timeout)
        def bottle_neck(node_1, target_type, path):
            return self.feature_calculator._prob_with_end_type(node_1, target_type, path)

        with open(self.save_file, "a+") as f:
            for s, data in enumerate(datas):
                if s % 10 == 0:
                    print('current test data: ', s)

                node_1 = data.strip()
                test_data_node_1 = defaultdict(lambda: [0] * len(self.feature_calculator.relation_paths))
                if node_1 not in self.feature_calculator.nodes.keys():
                    print("unregistered entity found: ", node_1)
                    continue  # process next vulnerability
                else:
                    for i, path in enumerate(self.feature_calculator.relation_paths):
                        # tem = self.feature_calculator._prob_with_end_type(node_1, target_type, path)
                        tem = bottle_neck(node_1, target_type, path)
                        if tem is None:
                            print("Timeout: " + str(node_1) + "\t" + str(path))
                            continue
                        for node_2, prob in tem.items():
                            test_data_node_1[(node_1, node_2)][i] = prob

                # test_data_node_1: defaultDict
                # key: (VUL, CPE)
                # test_data_node_1[key]: feature vector
                for key in test_data_node_1.keys():
                    # one VUL -[target_relation_type]-> multiple CPE, iterate over them
                    # if key[1], which is CPE, is not recorded in feature_calculator (very long index operatoin :<), then
                    # we compute the score of feature vector (above!!!)
                    if key[1] not in self.feature_calculator.nodes[key[0]].info[target_relation_type]:
                        res = self.model.predict([test_data_node_1[key]])
                        # confidence is a ndarray with shape (1,2)
                        confidence = self.model.predict_proba([test_data_node_1[key]])
                        if res[0] == 0 or confidence[0][1] < self.threshold:
                            continue
                        # only write positive prediction
                        # self.model.coef_ is a ndarray with shape (1, dim of weights)
                        predict_vector = self.model.coef_[0] * test_data_node_1[key]
                        # line format: (head, tail)  feature vector  dot product  confidence for class 1
                        buffer_str = str(key) + "\t" + str(test_data_node_1[key]) + "\t" + str(predict_vector) + "\t" + str(confidence[0][1]) + "\n"
                        f.write(buffer_str)

    def reasoning_all_by_feature(self, feature_file):
        f = open(feature_file, "r")
        datas = f.readlines()
        f.close()

        with open(self.save_file, 'w') as f:
            for i, data in enumerate(datas):
                sample = data.strip().split("\t")[0]
                data = eval(data.strip().split("\t")[1])
                res = self.model.predict([data])
                confidence = self.model.predict_proba([data])
                if res[0] == 0 or confidence[0][1] < self.threshold:
                    continue
                f.write(sample + "\t" + str(data) + "\t" + str(confidence[0][1]) + "\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    reasoning_all_parser = subparsers.add_parser(
        'reasoning_all', help='reasoning impact scope of all vulnerabilities'
    )
    reasoning_all_parser.add_argument('-gf', '--graph_file', default="data/test.graph.txt", type=str, help="Path of the graph data file")
    reasoning_all_parser.add_argument('-wf', '--weight_file', default="data/model/path.weights.1.txt", type=str, help="Path of the path weights")
    reasoning_all_parser.add_argument('-mf', '--model_file', default="data/model/model_1.pkl", type=str, help="Path of the saved model")
    reasoning_all_parser.add_argument('-pf', '--path_file', default="data/paths.threshold.txt", type=str, help="Path of the path file")
    reasoning_all_parser.add_argument('-tf', '--test_file', default="data/test.vul.txt", type=str, help="Path of the test file")
    reasoning_all_parser.add_argument('-sf', '--save_file', default="data/reasoning.result.txt", type=str, help="Path to be saved")
    reasoning_all_parser.add_argument('-ff', '--feature_file', default="data/test.txt", type=str, help="Path of the feature file")
    reasoning_all_parser.add_argument('-t', '--threshold', default=0.5, type=float, help="threshold of the reasoning")
    reasoning_all_parser.add_argument('-m', '--method', default="model", type=str, help="method used to reason all. 'manually', 'model', 'feature' are available")

    reasoning_all_parser.set_defaults(action='reasoning_all')
    args = parser.parse_args()

    reasoner = Reasoner(graph_file=args.graph_file, model_file=args.model_file,
                        path_file=args.path_file, test_file=args.test_file,
                        save_file=args.save_file, threshold=args.threshold)

    if args.action == 'reasoning_all':
        if args.method == 'model':
            reasoner.reasoning_all_by_model(target_type='CPE', target_relation_type='Scope_Of_Influences')

        elif args.method == 'feature':
            reasoner.reasoning_all_by_feature(feature_file=args.feature_file)

        elif args.method == 'manually':
            pass

        else:
            raise Exception("Error method.")
