import py2neo, json
import random


def get_positive_samples_from_file(datas, target_relation):
    """
    从文件中抽取正例
    :param datas: 从train.graph.dat中读取的三元组数据
    :param target_relation: 待推理的目标关系
    :return: 正例
    """
    positive_samples = set()
    count = 0

    for data in datas:
        [node, relation, next_node] = data.strip().split("\t")
        if relation == target_relation:
            positive_samples.add((node, next_node))
            count += 1
            print('positive_samples: ', count)

    return positive_samples


def get_negative_samples_from_file(datas, positive_samples, head_replace='VUL', tail_replace='CPE'):
    negative_samples = set()
    entities = set()
    head_replace_entities = set()
    tail_replace_entities = set()

    for data in datas:
        [node, relation, next_node] = data.strip().split("\t")
        entities.add(node)
        if node.split('$')[0] == head_replace:
            head_replace_entities.add(node)
        elif node.split('$')[0] == tail_replace:
            tail_replace_entities.add(node)

    positive_samples_list = list(positive_samples)
    head_replace_entities = list(head_replace_entities)
    tail_replace_entities = list(tail_replace_entities)

    limit = 10 * len(positive_samples_list)
    while len(negative_samples) < limit:
        print('neg length: ', len(negative_samples), '   limit: ', limit)
        neg_sample = list(random.choice(positive_samples_list))
        print('origin: ', neg_sample)
        head_or_tail = random.randint(0, 1)
        neg_sample[head_or_tail] = random.choice(head_replace_entities) if head_or_tail == 0 else random.choice(tail_replace_entities)
        print('after replace: ', neg_sample)
        if tuple(neg_sample) not in positive_samples:
            negative_samples.add(tuple(neg_sample))

    return negative_samples


def get_samples_from_file(data_path='data/train.graph.r100vul.txt', target_relation="`Scope Of Influences`", save_path="data/train.pairs.txt"):
    """
    从文件中抽取正例并构造负例，其中文件是VulGraph中的一个子图，其中包含这个子图中所有的三元组，例如train.graph.txt
    :param data_path: 文件路径
    :param target_relation: 待推理的目标关系
    :param save_path: 保存路径
    :return:
    """
    with open(data_path, "r") as f:
        datas = f.readlines()

    positive_samples = get_positive_samples_from_file(datas=datas, target_relation=target_relation)
    # negative_samples = get_negative_samples_from_file(datas=datas, positive_samples=positive_samples)
    negative_samples = get_negative_samples_from_file_direct(datas=datas, positive_samples=positive_samples)

    with open(save_path, 'w') as f:
        for ps in positive_samples:
            f.write(','.join(ps) + ": +\n")
        for ns in negative_samples:
            f.write(','.join(ns) + ": -\n")

    return positive_samples, negative_samples


def get_test_vul(save_path, category=None):
    neo4j_url = 'bolt://192.168.8.48:5052'
    graph = py2neo.Graph(neo4j_url, username="neo4j", password="123456")

    f = open('./data_linux_kernel/nvd_linux_affected_products_20201104.json', 'r')
    wrt = open(save_path, "a+")
    content = json.load(f)
    # key is CVE name
    for k in content:
        query = "match (v:VUL) where v.NVD_ID=\"" + k + "\" return id(v)"
        # print(query)
        node_id = graph.run(query).data()[0]['id(v)']
        # print(node_id)
        line = "VUL$" + str(node_id) + "$" + k + "\n"
        # print(line)
        wrt.write(line)
    f.close()
    wrt.close()


# add by Tong Cheng
def get_negative_samples_from_file_direct(datas, positive_samples, head_replace='VUL', tail_replace='CPE'):
    negative_samples = set()
    entities = set()
    head_replace_entities = set()
    tail_replace_entities = set()

    for data in datas:
        [node, relation, next_node] = data.strip().split("\t")
        entities.add(node)
        if node.split('$')[0] == head_replace:
            head_replace_entities.add(node)
        elif node.split('$')[0] == tail_replace:
            tail_replace_entities.add(node)

    positive_samples_list = list(positive_samples)
    head_replace_entities = list(head_replace_entities)
    tail_replace_entities = list(tail_replace_entities)

    for head in head_replace_entities:
        for tail in tail_replace_entities:
            negative_samples.add((head, tail))
    return negative_samples.difference(positive_samples)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    gen_train_sample_parser = subparsers.add_parser(
        'gen_train_sample', help='Generate pos and neg samples according to the target relation'
    )
    gen_train_sample_parser.add_argument('-r', '--relation', required=True, type=str, help="the target relation")
    gen_train_sample_parser.add_argument('-g', '--graph_path', required=True, type=str, help="Path of the graph file")
    gen_train_sample_parser.add_argument('-s', '--save_path', required=True, type=str, help="Path to be saved")
    gen_train_sample_parser.set_defaults(action='gen_sample')

    gen_test_vul_parser = subparsers.add_parser(
        'gen_test_vul', help='Generate vulnerabilities to be tested'
    )
    gen_test_vul_parser.add_argument('-s', '--save_path', required=True, type=str, help="Path to be saved")
    gen_test_vul_parser.add_argument('-c', '--category', default=None, type=str, help="category to be tested")
    gen_test_vul_parser.set_defaults(action='gen_test_vul')

    args = parser.parse_args()

    if args.action == 'gen_sample':
        # get_samples_from_file(data_path=args.file_path, target_relation=args.relation, save_path=args.save_path)
        get_samples_from_file(data_path=args.graph_path, target_relation=args.relation, save_path=args.save_path)
    elif args.action == 'gen_test_vul':
        get_test_vul(save_path=args.save_path, category=args.category)

