import json
import sys
import os
import shutil

# print script name
print("script name:", sys.argv[0])

if len(sys.argv) > 2:
    print("args")
    for arg in sys.argv[1:]:
        print(arg)
else:
    print("not right arg")
    sys.exit()

pwd=sys.argv[1]
distance_file = sys.argv[2]
orig_file=pwd+distance_file

if os.path.exists(orig_file):
    print("find file")
else:
    print("file not exist")
    sys.exit()

# backup
source_file = orig_file
destination_file = pwd+"zzz"+distance_file+".bak"

# use  shutil.copyfile() backup
# shutil.copyfile(source_file, destination_file)

# change file
with open(orig_file, 'r') as file:
    data = json.load(file)

for key, value in data.items():
    new_key = key
    if not isinstance(value, dict):
        continue
    new_value = value.copy()
    new_value[key] = 1
    data[key] = new_value

with open(orig_file, 'w') as file:
    json.dump(data, file, indent=4)





