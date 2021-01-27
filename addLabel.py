rd = open("kernel-exp-short/train.txt", "r")
pairs_rd = open("kernel-exp-short/train.pairs.txt", "r")
content = pairs_rd.readlines()
ptr = 0
wrt = open("kernel-exp-short/train.txt.label", "w")
for line in rd.readlines():
    try:
        head_tail = eval(line.split("\t")[0])
    except ValueError:
        print(line)
        continue
    a = content[ptr][:-4].split(',')
    tmp = eval(line.split("\t")[1])
    label = 1 if content[ptr][-2] == '+' else 0
    tmp.insert(0, label)
    b = str(head_tail) + "\t" + str(tmp) + "\n"
    wrt.write(b)
    ptr += 1
rd.close()
pairs_rd.close()
wrt.close()
