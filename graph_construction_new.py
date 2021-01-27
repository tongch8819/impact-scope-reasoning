import py2neo
import os, re, sys
import random
import json


def generate_graph(save_path, category=None, vul_limit=None, cpe_limit=None, baseon_cpe_limit=None, with_additional_basedon=False):
    neo4j_url = 'bolt://192.168.8.48:5052'
    graph = py2neo.Graph(neo4j_url, username="neo4j", password="123456")
    # if category:
    #     vuls = graph.run("match (n:VUL{category:'"+category+"'}) return distinct n").data()
    # else:
    #     vuls = graph.run("match (n:VUL) return distinct n").data()
    vuls = graph.run(r"match (n:VUL)-[:`Scope Of Influences`]->(c:CPE) where c.cpe23Uri=~'cpe:2.3:o:linux:linux_kernel.*' return distinct n").data()

    print('vuls num: ', len(vuls))
    if vul_limit:
        vuls = random.sample(vuls, vul_limit)
        print('random selected vuls num: ', len(vuls))
    vul_ids = list(set([item['n'].identity for item in vuls]))

    vul_cpe_tuples = list()
    for vul_id in vul_ids:
        tuples = graph.run(r"match (v:VUL)-[r:`Scope Of Influences`]->(cpe:CPE) where id(v)=" + str(vul_id) + " return distinct v,r,cpe").data()
        vul_cpe_tuples.extend(tuples)
    print('vul_cpe_tuples num: ', len(vul_cpe_tuples))
    if cpe_limit:
        vul_cpe_tuples = random.sample(vul_cpe_tuples, cpe_limit)
        print('random selected vul_cpe_tuples num: ', len(vul_cpe_tuples))
    cpe_ids = list(set([item['cpe'].identity for item in vul_cpe_tuples]))

    vul_cwe_tuples = graph.run(r"match (v:VUL)-[r:CausedBy]->(cwe:CWE) where id(v) in "+str(vul_ids)+" return distinct v,r,cwe").data()
    print('vul_cwe_tuples num: ', len(vul_cwe_tuples))
    cwe_ids = list(set([item['cwe'].identity for item in vul_cwe_tuples]))

    cpe_vendor_tuples = graph.run(r"match (cpe:CPE)<-[r:Develop]-(vendor:vendor) where id(cpe) in "+str(cpe_ids)+" return distinct vendor,r,cpe").data()
    print('cpe_vendor_tuples num: ', len(cpe_vendor_tuples))
    vendor_ids = list(set([item['vendor'].identity for item in cpe_vendor_tuples]))

    # cpe_software_tuples = graph.run("match (cpe:CPE)<-[r:HasCPEOf]-(software:software) where id(cpe) in " + str(cpe_ids) + " return distinct software,r,cpe").data()
    # print('cpe_software_tuples num: ', len(cpe_software_tuples))
    # software_ids = list(set([item['software'].identity for item in cpe_software_tuples]))

    cpe_cpe_tuples = graph.run(r"match (cpe1:CPE)-[r:BasedOn]->(cpe2:CPE) where id(cpe1) in " + str(cpe_ids) + " and id(cpe2) in " + str(cpe_ids) + " return distinct cpe1,r,cpe2").data()
    print('cpe_cpe_tuples num: ', len(cpe_cpe_tuples))

    cwe_cwe_tuples = graph.run(r"match (cwe1:CWE)-[r:ChildOf]->(cwe2:CWE) where id(cwe1) in " + str(cwe_ids) + " and id(cwe2) in " + str(cwe_ids) + " return distinct cwe1,r,cwe2").data()
    print('cwe_cwe_tuples num: ', len(cwe_cwe_tuples))

    # vendor_software_tuples = graph.run("match (vendor:vendor)-[r:DevelopProductOf]->(software:software) where id(vendor) in " + str(vendor_ids) + " and id(software) in " + str(software_ids) + " return distinct vendor,r,software").data()
    # print('vendor_software_tuples num: ', len(vendor_software_tuples))

    if with_additional_basedon:
        # 添加具有basedon模式的数据
        basedon_data = graph.run(r'match (v:VUL)-[r1:`Scope Of Influences`]->(cpe1:CPE)-[r0:BasedOn]->(cpe2:CPE)<-[r2:`Scope Of Influences`]-(v:VUL) return distinct v,cpe1,cpe2,r0,r1,r2').data()
        basedon_vul_ids = [item['v'].identity for item in basedon_data]
        _basedon_vul_cpe_tuples = [{'v': item['v'], 'cpe':item['cpe1'], 'r':item['r1']} for item in basedon_data] + [{'v': item['v'], 'cpe':item['cpe2'], 'r':item['r2']} for item in basedon_data]
        _basedon_vul_cpe_tuples_all = graph.run(r"match (v:VUL)-[r:`Scope Of Influences`]->(cpe:CPE) where id(v) in " + str(basedon_vul_ids) + " return distinct v,r,cpe").data()
        _basedon_vul_cpe_tuples = _basedon_vul_cpe_tuples + random.sample(_basedon_vul_cpe_tuples_all, baseon_cpe_limit)
        _basedon_cpe_cpe_tuples = [{'cpe1': item['cpe1'], 'cpe2':item['cpe2'], 'r':item['r0']} for item in basedon_data]

        # 去重
        basedon_vul_cpe_tuples = list()
        for item in _basedon_vul_cpe_tuples:
            if item not in vul_cpe_tuples and item not in basedon_vul_cpe_tuples:
                basedon_vul_cpe_tuples.append(item)
        print('basedon_vul_cpe_tuples num: ', len(basedon_vul_cpe_tuples))

        basedon_cpe_cpe_tuples = list()
        for item in _basedon_cpe_cpe_tuples:
            if item not in cpe_cpe_tuples and item not in basedon_cpe_cpe_tuples:
                basedon_cpe_cpe_tuples.append(item)
        print('basedon_cpe_cpe_tuples num: ', len(basedon_cpe_cpe_tuples))

    with open(save_path, 'w') as f:
        for item in vul_cpe_tuples:
            head = 'VUL$' + str(item['v'].identity) + '$' + item['v']['NVD_ID']
            tail = 'CPE$' + str(item['cpe'].identity) + '$' + item['cpe']['cpe23Uri']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        for item in vul_cwe_tuples:
            head = 'VUL$' + str(item['v'].identity) + '$' + item['v']['NVD_ID']
            tail = 'CWE$' + str(item['cwe'].identity) + '$' + item['cwe']['CWE_ID']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        for item in cpe_vendor_tuples:
            head = 'vendor$' + str(item['vendor'].identity) + '$' + item['vendor']['vendor_name']
            tail = 'CPE$' + str(item['cpe'].identity) + '$' + item['cpe']['cpe23Uri']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        # for item in cpe_software_tuples:
        #     head = 'software$' + str(item['software'].identity) + '$' + item['software']['software_name']
        #     tail = 'CPE$' + str(item['cpe'].identity) + '$' + item['cpe']['cpe23Uri']
        #     f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
        #     f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        for item in cpe_cpe_tuples:
            head = 'CPE$' + str(item['cpe1'].identity) + '$' + item['cpe1']['cpe23Uri']
            tail = 'CPE$' + str(item['cpe2'].identity) + '$' + item['cpe2']['cpe23Uri']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        for item in cwe_cwe_tuples:
            head = 'CWE$' + str(item['cwe1'].identity) + '$' + item['cwe1']['CWE_ID']
            tail = 'CWE$' + str(item['cwe2'].identity) + '$' + item['cwe2']['CWE_ID']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        # for item in vendor_software_tuples:
        #     head = 'vendor$' + str(item['vendor'].identity) + '$' + item['vendor']['vendor_name']
        #     tail = 'software$' + str(item['software'].identity) + '$' + item['software']['software_name']
        #     f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
        #     f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

        if with_additional_basedon:
            for item in basedon_vul_cpe_tuples:
                head = 'VUL$' + str(item['v'].identity) + '$' + item['v']['NVD_ID']
                tail = 'CPE$' + str(item['cpe'].identity) + '$' + item['cpe']['cpe23Uri']
                f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
                f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')

            for item in basedon_cpe_cpe_tuples:
                head = 'CPE$' + str(item['cpe1'].identity) + '$' + item['cpe1']['cpe23Uri']
                tail = 'CPE$' + str(item['cpe2'].identity) + '$' + item['cpe2']['cpe23Uri']
                f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
                f.write('\t'.join([tail, type(item['r']).__name__+'_inv', head]) + '\n')


def generate_graph_from_file(file_path, save_path, vul_limit=None, cpe_limit=None):
    neo4j_url = 'bolt://192.168.8.48:5052'
    graph = py2neo.Graph(neo4j_url, username="neo4j", password="123456")

    with open(file_path, 'r') as f:
        cve_cpe_data = json.load(f)

    vul_cves = cve_cpe_data.keys()
    vuls = [graph.run(r"match (n:VUL{NVD_ID:'" + cve + "'}) return distinct n").data()[0] for cve in cve_cpe_data.keys()]

    assert len(vul_cves) == len(vuls)

    print('vuls num: ', len(vuls))
    if vul_limit:
        vuls = random.sample(vuls, vul_limit)
        print('random selected vuls num: ', len(vuls))
    vul_ids = list(set([item['n'].identity for item in vuls]))

    vul_cpe_tuples = list()
    for vul in vuls:
        cve = vul['n']['NVD_ID']
        tuples = list()
        for cpe in cve_cpe_data[cve]:
            try:
                query = "match (v:VUL{NVD_ID:'" + cve + "'})-[r:`Scope Of Influences`]->(cpe:CPE{cpe23Uri:'" + cpe + "'}) return distinct v,r,cpe"
                if re.search("\\\\", query) is not None:
                    tuple = graph.run(repr(query)[1:-1]).data()[0]  # expand escape char
                else:
                    tuple = graph.run(query).data()[0]
                tuples.append(tuple)
            except Exception as e:
                # print(cve)
                # print(cpe)
                # print(e)
                sys.stderr.write(str(cve) + '\n' + str(cpe) + '\n' +  str(e) + '\n\n')
#                break
#        assert len(tuples) == len(cve_cpe_data[cve])
        vul_cpe_tuples.extend(tuples)
        print('current cve: ', cve)
        print('current cpe tuples num: ', len(vul_cpe_tuples))
    print('vul_cpe_tuples num: ', len(vul_cpe_tuples))
    if cpe_limit:
        vul_cpe_tuples = random.sample(vul_cpe_tuples, cpe_limit)
        print('random selected vul_cpe_tuples num: ', len(vul_cpe_tuples))
    cpe_ids = list(set([item['cpe'].identity for item in vul_cpe_tuples]))

    vul_cwe_tuples = graph.run(r"match (v:VUL)-[r:CausedBy]->(cwe:CWE) where id(v) in " + str(vul_ids) + " return distinct v,r,cwe").data()
    print('vul_cwe_tuples num: ', len(vul_cwe_tuples))
    cwe_ids = list(set([item['cwe'].identity for item in vul_cwe_tuples]))

    cpe_vendor_tuples = graph.run(r"match (cpe:CPE)<-[r:Develop]-(vendor:vendor) where id(cpe) in " + str(
        cpe_ids) + " return distinct vendor,r,cpe").data()
    print('cpe_vendor_tuples num: ', len(cpe_vendor_tuples))
    vendor_ids = list(set([item['vendor'].identity for item in cpe_vendor_tuples]))

    cpe_cpe_tuples = graph.run(
        r"match (cpe1:CPE)-[r:BasedOn]->(cpe2:CPE) where id(cpe1) in " + str(cpe_ids) + " and id(cpe2) in " + str(
            cpe_ids) + " return distinct cpe1,r,cpe2").data()
    print('cpe_cpe_tuples num: ', len(cpe_cpe_tuples))

    cwe_cwe_tuples = graph.run(
        r"match (cwe1:CWE)-[r:ChildOf]->(cwe2:CWE) where id(cwe1) in " + str(cwe_ids) + " and id(cwe2) in " + str(
            cwe_ids) + " return distinct cwe1,r,cwe2").data()
    print('cwe_cwe_tuples num: ', len(cwe_cwe_tuples))

    with open(save_path, 'w') as f:
        for item in vul_cpe_tuples:
            head = 'VUL$' + str(item['v'].identity) + '$' + item['v']['NVD_ID']
            tail = 'CPE$' + str(item['cpe'].identity) + '$' + item['cpe']['cpe23Uri']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__ + '_inv', head]) + '\n')

        for item in vul_cwe_tuples:
            head = 'VUL$' + str(item['v'].identity) + '$' + item['v']['NVD_ID']
            tail = 'CWE$' + str(item['cwe'].identity) + '$' + item['cwe']['CWE_ID']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__ + '_inv', head]) + '\n')

        for item in cpe_vendor_tuples:
            head = 'vendor$' + str(item['vendor'].identity) + '$' + item['vendor']['vendor_name']
            tail = 'CPE$' + str(item['cpe'].identity) + '$' + item['cpe']['cpe23Uri']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__ + '_inv', head]) + '\n')

        for item in cpe_cpe_tuples:
            head = 'CPE$' + str(item['cpe1'].identity) + '$' + item['cpe1']['cpe23Uri']
            tail = 'CPE$' + str(item['cpe2'].identity) + '$' + item['cpe2']['cpe23Uri']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__ + '_inv', head]) + '\n')

        for item in cwe_cwe_tuples:
            head = 'CWE$' + str(item['cwe1'].identity) + '$' + item['cwe1']['CWE_ID']
            tail = 'CWE$' + str(item['cwe2'].identity) + '$' + item['cwe2']['CWE_ID']
            f.write('\t'.join([head, type(item['r']).__name__, tail]) + '\n')
            f.write('\t'.join([tail, type(item['r']).__name__ + '_inv', head]) + '\n')


def remove_space(save_path):
    with open(save_path, 'r') as f:
        lines = f.readlines()

        for i, l in enumerate(lines):
            lines[i] = l.replace(' ', '_')

    with open(save_path, 'w') as fw:
        fw.writelines(lines)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--file_path', required=True, type=str, help="Path of cve and cpe data")
    parser.add_argument('-s', '--save_path', required=True, type=str, help="Path to be saved")
    parser.add_argument('-c', '--category', default=None, type=str, help="category to be tested")
    parser.add_argument('-vl', '--vul_limit', default=None, type=int, help="amount limitation of vulnerabilities")
    parser.add_argument('-m', '--mode', default='neo4j', type=str, help="neo4j or file")

    args = parser.parse_args()

    if os.path.isdir(args.save_path):
        raise Exception("Error Path")
    else:
        if args.mode == 'neo4j':
            generate_graph(args.save_path, category=args.category, vul_limit=int(args.vul_limit))
            remove_space(args.save_path)
        elif args.mode == 'file':
            # generate_graph_from_file(file_path=args.file_path, save_path=args.save_path, vul_limit=int(args.vul_limit))
            generate_graph_from_file(file_path=args.file_path, save_path=args.save_path, vul_limit=args.vul_limit)
            remove_space(args.save_path)
        else:
            raise Exception("Error mode")






