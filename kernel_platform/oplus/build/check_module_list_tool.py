import os
import subprocess
import sys

#print("input length is：", len(sys.argv))
#print("input type:", type(sys.argv))
#print("function name:", sys.argv[0])
try:
    print("input base file:", sys.argv[1])
    print("input local file:", sys.argv[2])

except Exception as e:
    print("Input Error:", e)

module_base = sys.argv[1]
module_local = sys.argv[2]

cat_module_base = "cat {}".format(module_base)
cat_module_local = "cat {}".format(module_local)

out_module_local_list = []
p_module_base = subprocess.Popen(cat_module_base, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
p_module_local = subprocess.Popen(cat_module_local, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

out_module_base_list = []
for line in p_module_base.stdout.readlines():
    out_module_base_list.append(str(line, encoding="utf-8"))

for line in p_module_local.stdout.readlines():
    line = str(line, encoding="utf-8")
    if line not in out_module_base_list:
        out_module_local_list.append(line)
        print(line)
        with open(module_base, 'a') as file_object:
            file_object.write(line)

def document_deduplication(document_name):
    current_list = []
    for i in open(document_name):
        if i not in current_list:
            current_list.append(i)
    with open('current_tmp.txt', 'w') as handle:
        handle.writelines(current_list)
    os.remove(document_name)
    os.rename('current_tmp.txt', document_name)

document_deduplication(module_base)