from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support
from sklearn.metrics import precision_score, recall_score
import pickle
import numpy as np


class Model:
    def __init__(self, feature_file, path_num):

        self.feature_file = feature_file
        self.features = []
        self.tuples = []
        self.labels = []
        self.coef = []
        self.test_result = []
        self.test_details = []
        self.path_num = path_num
        self.data_preprocess()
        self.path_ids = [n for n in range(self.path_num)]

    def data_preprocess(self):

        with open(self.feature_file, "r") as f:
            datas = f.readlines()
            for i, data in enumerate(datas):
                tupl = data.strip().split("\t")[0]
                data = eval(data.strip().split("\t")[1])
                try:
                    assert len(data) == self.path_num + 1
                    self.labels.append(data[0])
                    self.features.append(data[1:])
                    self.tuples.append(tupl)
                except AssertionError:
                    print('Error data item in line: ', i)

    def train(self, stop_loss=0.001, max_iter=10000):
        self.model = LogisticRegression(
            C=0.6,
            random_state=20,
            penalty="l2",
            solver="saga",
            tol=stop_loss,
            class_weight='balanced',
            max_iter=max_iter,
            verbose=1
        )

        # same random seed, same divide
        random_seed = 10
        X_train_tuple, X_test_tuple, _, _ = train_test_split(self.tuples, self.labels, test_size=0.3, random_state=random_seed)
        X_train, X_test, y_train, y_test = train_test_split(self.features, self.labels, test_size=0.3, random_state=random_seed)
        print('---- X_train ----: ', X_train)
        print('---- y_train ----: ', y_train)
        self.model.fit(X_train, y_train)

        # print(self.model.intercept_)
        # X = X_test[0]
        # X = [[0.01, 0.0, 0.0, 0.0, 0.0, 0.0]]
        # print(X)
        # print(self.model.coef_.T)
        # score = np.dot(X, self.model.coef_.T) + self.model.intercept_
        # print(score)
        # print(1. / (1. + np.exp(-score)))
        # print(self.model.predict_proba(X))
        # print(self.model.predict(X))

        self.coef = self.model.coef_[0]

        for X, tupl in zip(X_test, X_test_tuple):
            feature = X
            product = np.array(self.coef) * np.array(feature)
            proba = self.model.predict_proba([X])
            self.test_details.append('\t'.join([str(tupl), str(feature), str(product), str(proba)]))

        self.test_result = precision_recall_fscore_support(y_test, self.model.predict(X_test))
        return

    def save(self, model_file, result_file="result.txt", coef_file="path.weights", details_file="test_details.txt"):
        with open(model_file, "wb") as f:
            pickle.dump(self.model, f)

        with open(result_file, "w") as f:
            for result in self.test_result:
                f.write(str(result) + "\n")

        with open(coef_file, "w") as f:
            for n, c in enumerate(self.coef):
                f.write(str(self.path_ids[n]) + "\t" + str(c) + "\n")

        with open(details_file, 'w') as f:
            for detail in self.test_details:
                f.write(str(detail) + "\n")
        return

    def path_selection(self, threshold=0.001):
        tem = []
        for n, c in enumerate(self.coef):
            if abs(c) > threshold:
                tem.append(self.path_ids[n])
            else:
                continue
        self.path_ids = tem
        del tem
        return

    def retrain(self, stop_loss=0.0001, max_iter=100000):
        for m, feature in enumerate(self.features):
            tem = []
            for n, v in enumerate(feature):
                if n in self.path_ids:
                    tem.append(v)
            self.features[m] = tem
            del tem
        self.train(stop_loss=stop_loss, max_iter=max_iter)


if __name__ == "__main__":
    import argparse
    import os
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--save_path', default="data/model/", type=str, help="Path to be saved")
    parser.add_argument('-f', '--feature_path', default="data/train.txt", type=str, help="Path of filtered paths to be saved")
    parser.add_argument('-p', '--path_num', default=6, type=int, help="Number of Path in the graph file")

    args = parser.parse_args()

    model = Model(feature_file=args.feature_path, path_num=args.path_num)
    print('------------- train -------------')
    model.train(stop_loss=0.0001, max_iter=100000)
    model.save(os.path.join(args.save_path, "model_1.pkl"), os.path.join(args.save_path, "result_1.txt"),
               os.path.join(args.save_path, "path.weights.1.txt"), os.path.join(args.save_path, "test.details.1.txt"))

    # model.path_selection(threshold=0.01)
    # print('------------- retrain 1 -------------')
    # model.retrain()
    # model.save(path + "model_2.pkl", path + "result_2.txt", path + "path.weights.2.txt")
    # model.path_selection(threshold=0.1)
    # print('------------- retrain 2 -------------')
    # model.retrain()
    # model.save(path + "model_3.pkl", path + "result_3.txt", path + "path.weights.3.txt")
    # model.path_selection(threshold=0.1)
    # print('------------- retrain 3 -------------')
    # model.retrain()
    # model.save(path + "model_4.pkl", path + "result_4.txt", path + "path.weights.4.txt")

    # with open('data_vulgraph_20201012/model/model_1.pkl', 'rb') as f:
    #     model = pickle.load(f)
    #     a = model.predict([[0.015625, 0, 0, 0, 0, 0]])
    #     print(a)
    #     b = model.predict_proba([[0.00047664442326024784, 0, 0, 0, 0.125, 0]])
    #     print(b)
