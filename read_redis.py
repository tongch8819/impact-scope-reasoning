import redis
import json

all_pool = redis.ConnectionPool(host='192.168.8.18', port=6379, db=0, password='123456', decode_responses=True)
r_all = redis.Redis(connection_pool=all_pool)

if __name__ == "__main__":
    # print(r_all.keys())
    globals = {
        'true': 0,
        'false': 1,
        'null': 0
    }
    # result = r_all.hkeys('nvd')
    cve = json.loads(json.dumps(eval(r_all.hget('cpe', 'CVE-2015-8438'), globals)))
    # print(json.dumps(eval(r_all.hget('cpe', 'CVE-2015-8438'), globals), sort_keys=True, indent=4, separators=(', ', ': ')))
    print(cve)
    # print(cve['cpe'][0])
