import json
import sys
import os
import shutil

# print script name
print("脚本名称:", sys.argv[0])

if len(sys.argv) > 2:
    print("args")
    for arg in sys.argv[1:]:
        print(arg)
else:
    print("not right arg")
    sys.exit()

pwd = sys.argv[1]
targets_file = sys.argv[2]
orig_file = pwd+targets_file

if os.path.exists(orig_file):
    print("find file")
else:
    print("file not exist")
    sys.exit()


# change file
with open(orig_file, 'r') as file:
    lines = file.readlines()

new_lines = []
for line in lines:
    if ":" in line:
        new_line = line.split(":")[0]
        new_lines.append(new_line)
    else:
        new_line = line.strip()
        new_lines.append(new_line)

new_lines_times = {}
for new_line in new_lines:
    if new_line not in new_lines_times:
        new_lines_times[new_line] = 1
    else:
        new_lines_times[new_line] += 1

add_at_end=[]
with open(orig_file, 'w') as file:
    for line, n in new_lines_times.items():
        if n == 1:
            file.write(line + "\n")
        elif n <1:
            file.write("not right times\n")
            print("not right times")
            exit(1)
    for line, n in new_lines_times.items():
        if n > 1:
            for _ in range(n):
                file.write(line + "\n")


