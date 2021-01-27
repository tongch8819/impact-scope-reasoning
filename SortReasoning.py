import sys, os

with open("kernel-exp-short/reasoning.result.txt", "r") as rd:
    content = rd.readlines()
print("Scale: {}".format(len(content)))

def func(start):
    container = []
    # for i in range(int(sys.argv[1]), len(content), 2):
    i = start
    for i in range(start, len(content), 2):
        try:
            val = eval(content[i].split("\t")[-1])
        except SyntaxError:
            print(i, file=sys.stderr)
            break
    #     print(type(val), val)
        percentage = i/len(content)
        charactor = int(100*percentage)
        print("\r {} {}".format('-'*charactor, percentage), end="")
        container.append(str(val)+"\n")

    with open("kernel-exp-short/confidence.txt", "a+") as wrt:
        wrt.writelines(container)
        print("\nWrite Success")
    return i

def main():
    start = 1
    while True:
        # with open("kernel-exp-short/sort.log", 'r') as rd:
        #     line = rd.readlines()[0]
        # start = eval(line) + 1

        bp = func(start)
        if bp == len(content):
            break
        else:
            start = bp + 1


if __name__ == "__main__":
    main()