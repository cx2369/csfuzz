import os
import re
import subprocess

put = "/home/cas/put/pdftotext/pdftotext-asan"
args = "@@ /dev/null"
crash_dir = "/home/cas/default/crashes"

crash_file_list = []


def extract_asan_callstack(err_msg, max_func=5):
    patt = r'#\d+ 0x[0-9a-fA-F]+ in (\w+)'
    match_list = re.findall(patt, err_msg)
    if len(match_list) > max_func:
        match_list = match_list[:max_func]
    return match_list


for root, dirs, files in os.walk(crash_dir):
    for file in files:
        crash_file_list.append(os.path.abspath(os.path.join(root, file)))

__all_san_map = dict()
__fuzzer_list = ['csfuzz']
for __fuzzer in __fuzzer_list:
    __all_san_map[__fuzzer] = []

for file in crash_file_list:

    if args.find('@@') == -1:
        _stdin_fd = open(file)
    else:
        _stdin_fd = subprocess.PIPE

    _cur_args = args.replace('@@', file)
    all_cmd = [put]
    all_cmd.extend(_cur_args.split(' '))
    try:
        p = subprocess.run(all_cmd, stdin=_stdin_fd,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        err_msg = p.stderr.decode('utf-8', 'ignore')
        lpos = err_msg.find('ERROR: AddressSanitizer: ')
        if lpos == -1 and err_msg.find('ERROR: LeakSanitizer: '):
            btype = 'mem-leak'
            err_msg = err_msg[err_msg.find('ERROR: LeakSanitizer: '):]
        else:
            btype = err_msg[lpos + 25:][:err_msg[lpos + 25:].find(' ')]
            err_msg = err_msg[lpos:]

        if btype == 'heap-use-after-free':
            free_pos = err_msg.find('freed by thread')
            alloc_pos = err_msg.find('previously allocated by')
            use_msg = err_msg[:free_pos]
            free_msg = err_msg[free_pos: alloc_pos]
            alloc_msg = err_msg[alloc_pos:]
            ret = extract_asan_callstack(use_msg, 3)
            stack_trace = '->'.join(ret)
        elif btype == 'stack-overflow':
            ret = extract_asan_callstack(err_msg, 3)
            stack_trace = '->'.join(ret)
        else:
            ret = extract_asan_callstack(err_msg, 3)
            stack_trace = '->'.join(ret)
        type_stack_trace = btype + ' : ' + stack_trace
        if type_stack_trace not in __all_san_map['csfuzz'] and stack_trace != '':
            __all_san_map['csfuzz'].append(type_stack_trace)

    except:
        print('[WARN] while validating, seed %s timeout, skip' % (file))

for key, value in __all_san_map.items():
    print(key)
    print(len(value))
    for value_item in value:
        print(value_item)


