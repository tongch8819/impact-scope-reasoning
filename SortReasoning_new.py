import sys, os

with open("kernel-exp-short/reasoning.result.txt", "r") as rd:
    content = rd.readlines()
print("Scale: {}".format(len(content)))

def func():
    lines = []
    mark = True
    for i, line in enumerate(content):
        if mark:
            tmp = ""
        try:
            val = eval(line.split("\t")[-1])
            tmp += line
            lines.append(tmp)
            mark = True
        except SyntaxError:
            # tmp += line.replace("\n", "")
            tmp += line.split("\n")[0]
            mark = False
    return lines

def main():
    lines = func()
    with open("kernel-exp-short/reasoning.result.txt.cleaned", "w") as wrd:
        wrd.writelines(lines)
        print("Write finished")


if __name__ == "__main__":
    main()