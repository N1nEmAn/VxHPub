import os
from concurrent.futures import ThreadPoolExecutor
import binwalk
import struct
import subprocess

# Constants for colored output
BLUE = '\033[34m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'
YELLOW = "\033[93m"
def find_largest_file(directory):
    largest_file = None
    largest_size = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            if "files" in file:
                continue  # 忽略文件名包含“files”的文件
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            if file_size > largest_size:
                largest_file = file_path
                largest_size = file_size
    
    print(f"{GREEN}[+]{END} Found largest file_path: {largest_file}")
    return largest_file

def u32(data):
    """Big endian"""
    return struct.unpack(">I", data)[0]

def read_file(path):
    try:
        with open(path, "rb") as fd:
            content = fd.read()
            fd.close()
        return content
    except IOError:
        print(f"{RED}[-]{END} Open target firmware failed: {path}")
        exit(-1)

def find_loading_addr(path, arch):
    content = read_file(path)
    addr = None  # 初始化 addr 变量

    myfirmware_str_offset = content.find(b"MyFirmware")
    if myfirmware_str_offset == -1:
        print(f"{YELLOW}[*]{END} Can't find 'MyFirmware' string in {path}")
    else:
        addr_str_offset = myfirmware_str_offset - 0xc0 + 0x18
        addr = u32(content[addr_str_offset: addr_str_offset + 4])
        if addr:
            print(f"{GREEN}[+]{END} Found loading_addr address: {hex(addr)}")
            return addr

    # 如果没有找到 "MyFirmware" 或地址无效，继续寻找其他信息
    print(f"{YELLOW}[*]{END} Find MyFirmware address failed in {path}")

    img_addr_str_offset = content.find(b"img addr")
    if img_addr_str_offset == -1:
        u_boot_image_addr = content.find(b"u-boot image")
        if u_boot_image_addr == -1:
            # 如果找不到任何有效的地址，返回基于架构的默认地址
            default_addr = 0x40205000 if "arm" in arch else 0x80001000
            print(f"{YELLOW}[*]{END} Using default address {hex(default_addr)} based on architecture")
            return default_addr

        addr_str_offset = u_boot_image_addr - 0x10
        addr = u32(content[addr_str_offset: addr_str_offset + 4])
        if addr:
            print(f"{GREEN}[+]{END} Found u-boot image address: {hex(addr)}")
            return addr
        else:
            print(f"{RED}[-]{END} Find u-boot image address failed!")
            return 0

    addr_str_offset = img_addr_str_offset + len('img addr: ')
    count = addr_str_offset
    while content[count] not in (0, 10):  # 查找行末
        count += 1

    addr_str = content[addr_str_offset: count].decode('utf-8')
    try:
        addr = eval(addr_str)
        print(f"{GREEN}[+]{END} Found img addr address: {hex(addr)}")
        return addr
    except Exception as e:
        print(f"{RED}[-]{END} Find address failed! Exception: {e}")
        return 0

# 定义 ang 识别的架构匹配列表
ARCHITECTURES = {
    'x86': 'x86',
    'x86_64': 'x86_64',
    'arm': 'arm',
    'arm64': 'arm64',
    'mips': 'mips',
    'mips64': 'mips64',
    'powerpc': 'powerpc',
    'ppc64': 'ppc64',
    'sparc': 'sparc',
    'sparc64': 'sparc64',
    'riscv': 'riscv',
    'riscv64': 'riscv64',
    'alpha': 'alpha',
    'sh': 'sh',
    'ia64': 'ia64',
    'hppa': 'hppa',
}

ENDIANNESS = {
    'little': 'little',
    'big': 'big',
    'unknown': 'unknown',
}
def get_file_architecture_endi(file_path):
    try:
        # 执行 binwalk 命令获取输出
        output = subprocess.check_output(['binwalk', '-Y', file_path], stderr=subprocess.STDOUT, universal_newlines=True)
        # 解析输出并提取架构信息
        lines = output.strip().split('\n')
        
        # # 打印所有行以便调试
        # for line in lines:
        #     print(line)
        
        # 初始化匹配结果
        arch_match = 'unknown'
        endian_match = 'unknown'
        
        # 遍历每一行寻找架构和大小端信息
        for line in lines:
            # 遍历架构字典的键
            for arch_key in ARCHITECTURES:
                if arch_key in line.lower():
                    arch_match = ARCHITECTURES[arch_key]
                    break
            # 遍历大小端字典的键
            for endian_key in ENDIANNESS:
                if endian_key in line.lower():
                    endian_match = ENDIANNESS[endian_key]
                    break

        print(f"{GREEN}[+]{END} Architecture: {arch_match}")
        print(f"{GREEN}[+]{END} Endianness: {endian_match}")
        return arch_match, endian_match

    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]{END} Error executing binwalk: {e}")
        return None, None

def check_file(file_path):
    if os.path.getsize(file_path) < 80 * 1024 or 'symbol_table' in file_path:
        return None
    
    try:
        print(f"{BLUE}[!]{END} Size of {file_path}: {os.path.getsize(file_path)//1024}Kb..")
        result = subprocess.run(
            ['binwalk', '-Y', file_path],
            capture_output=True,
            text=True,
            timeout = 10
        )
        if 'instructions' in result.stdout.lower():
            print(f"{GREEN}[+]{END} Found instructions in {file_path}")
            return file_path
    except Exception as e:
        print(f"{YELLOW}[*]{END} Error processing file {file_path}: {e}")

    return None

def find_maybe_firm_files(directory="."):
    maybe_firm = []

    # Traverse all files in the directory
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                futures.append(executor.submit(check_file, file_path))
        
        for future in futures:

            result = future.result()
            if result:
                maybe_firm.append(result)
    for file in maybe_firm:
        if "files" in file:
            maybe_firm.remove(file)
    if maybe_firm:
        print(f"\n{GREEN}[+]{END} Potential firm files found:")
        for firm_file in maybe_firm:
            print(f"{YELLOW}[*]{END} - {firm_file}")
    else:
        print(f"{GREEN}[-]{END} No potential firm files found.")
    
    return maybe_firm
def get_firm_arch(firm, directory="./extracted"):
    # firm = find_largest_file(directory)
    firm_arch, endian_arch = get_file_architecture_endi(firm)
    return firm_arch, endian_arch

def get_load_firm_arch_endian(firm, firmsum, firmbin = "./wdr7660gv1-cn-up_2019-08-30_10.37.02.bin"):
    firm_arch, endian_arch = get_firm_arch(firm)
    loading_addr = find_loading_addr(firmsum, firm_arch)
    return loading_addr, firm_arch, endian_arch

def main(firmbin = "./wdr7660gv1-cn-up_2019-08-30_10.37.02.bin"):
    firm, firm_arch, endian_arch = get_firm_arch()
    loading_addr = find_loading_addr(firmbin,arch)
    return loading_addr, firm, firm_arch, endian_arch

if __name__ == "__main__":
    main()

