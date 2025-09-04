path = input()
with open(path) as f:
    for s_line in f:
        print(hex(int(s_line.strip(),16)+4))