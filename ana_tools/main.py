#!/usr/bin/python3
import argparse
import time
import json
import os
from unpack_firm import *
from get_firmname_loadadd_arch import *

'''
分为获取固件、解压固件、提取固件、分析固件
'''

END = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = '\033[34m'

def time_logger(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Execution time of {func.__name__}: {end_time - start_time:.2f} seconds")
        return result
    return wrapper

def get_firmware():
    parser = argparse.ArgumentParser(description="firmware analyser")
    parser.add_argument("firmware_bin", help="Path to the firmware")
    return parser.parse_args()

def save_analysis_details(firm, loading_addr, firm_arch, endian_arch, output_dir="./result"):
    details = {
        "firmware": firm,
        "loading_address": hex(loading_addr),
        "architecture": firm_arch,
        "endianness": endian_arch,
    }
    new_firm_name = firm.replace("./extracted/","")
    output_dir = os.path.join("./result",f"{new_firm_name}_graph")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"analysis_details.json")

    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            existing_data = json.load(f)
        existing_data.append(details)
    else:
        existing_data = [details]
    
    with open(output_file, "w") as f:
        json.dump(existing_data, f, indent=4)
    print(f"{GREEN}[+]{END} Analysis details saved to {output_file}")

@time_logger
def main():
    # 通过命令行获取固件
    args = get_firmware()
    print(f"{GREEN}[+]{END} Firmware analysis started.")
    print(f"{GREEN}[+]{END} Firmware path acquired.")
    print()
    
    # 解压,结果会在extracted目录下
    unpack_lzma(args.firmware_bin)
    print(f"{GREEN}[+]{END} Firmware unpacked successfully.")
    print()

    # 分析出可能的固件/内核等，进行分析,并且对固件主体命名
    maybe_list = find_maybe_firm_files("./extracted/")
    # maybe_list = rename_firm_master(maybe_list)
    for firm in maybe_list:
        # 获取加载地址、固件路径、架构、端序,对其进行分析
        loading_addr, firm_arch, endian_arch = get_load_firm_arch_endian(firm, args.firmware_bin, args.firmware_bin)
        if firm_arch == "unknown" or "files" in firm:
            print(f"{YELLOW}[*]{END} {firm} is not executable...")
            continue
        print(f"{YELLOW}[*]{END} Analyzing {firm}...")
        if firm_arch == "unknown" or "files" in firm:
            print(f"{YELLOW}[*]{END} {firm} is not executable...")
            continue
        print(f"{GREEN}[+]{END} Firmware details extracted.")
        print()
        
        # 保存分析细节到 JSON 文件
        save_analysis_details(firm, loading_addr, firm_arch, endian_arch)
        
    print(f"{GREEN}[+]{END} Analysis completed successfully! The result is in the folder ./result")

if __name__ == "__main__":
    main()

