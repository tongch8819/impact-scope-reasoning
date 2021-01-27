import os, re


def buildMapping(directory):
    if not os.path.isdir(directory):
        return None
    directory = os.path.abspath(directory)
    rst = []
    for name in os.listdir(directory):
        regex = re.search("train.txt.cumul.start*", name)
        if regex is not None:
            with open(directory+"/"+name, "r") as rd:
                length = len(rd.readlines())
            rst.append((eval(name.split('t')[-1]), length))
    return {x:y for x, y in rst}

def main():
    mapping = buildMapping(directory="./kernel-exp")
    print(mapping)


if __name__ == "__main__":
    main()