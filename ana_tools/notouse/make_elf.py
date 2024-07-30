from capstone import *
from pwn import context
from pwnlib.elf.datatypes import *
from get_firmname_loadadd_arch import *
import struct

# 定义颜色常量
YELLOW = "\033[93m"
GREEN = "\033[92m"
END = "\033[0m"

# 定义用于 ELF 头的架构字典
elf_arch_map = {
    'x86': 0x03,          # Intel 80386
    'x86_64': 0x3E,       # AMD x86-64
    'arm': 0x28,          # ARM
    'arm64': 0xB7,        # AArch64 (ARM64)
    'mips': 0x08,         # MIPS
    'mips64': 0x08,       # MIPS
    'powerpc': 0x14,      # PowerPC
    'powerpc64': 0x15,    # PowerPC64
    'sparc': 0x02,        # SPARC
    'sparc64': 0x2B,      # SPARC64
    'riscv': 0xF3,        # RISC-V
}

# 定义用于 Capstone 反汇编的架构字典
cs_arch_map = {
    'x86': (CS_ARCH_X86, CS_MODE_32),
    'x86_64': (CS_ARCH_X86, CS_MODE_64),
    'arm': (CS_ARCH_ARM, CS_MODE_ARM),
    'arm64': (CS_ARCH_ARM64, CS_MODE_ARM),
    'mips': (CS_ARCH_MIPS, CS_MODE_32),
    'mips64': (CS_ARCH_MIPS, CS_MODE_64),
    'powerpc': (CS_ARCH_PPC, CS_MODE_32),
    'powerpc64': (CS_ARCH_PPC, CS_MODE_64),
    'sparc': (CS_ARCH_SPARC, CS_MODE_32),
    'sparc64': (CS_ARCH_SPARC, CS_MODE_64),
    'riscv': (CS_ARCH_RISCV, CS_MODE_RISCV32),
}

# 定义端序字典
endian_map = {
    'little': 1,  # ELFDATA2LSB 的值
    'big': 2     # ELFDATA2MSB 的值
}

def get_arch_info():
    """获取架构信息"""
    firm, firmarch, firmendness = get_firm_arch()
    elf_arch = elf_arch_map.get(firmarch)
    cs_arch, cs_mode = cs_arch_map.get(firmarch, (None, None))
    endian = endian_map.get(firmendness)
    
    if elf_arch is None or cs_arch is None or endian is None:
        raise ValueError(f"Unsupported architecture or endianness: {firmarch}, {firmendness}")
    
    return firm, elf_arch, cs_arch, cs_mode, endian

def analyze_binary(binary_data, cs_arch, cs_mode):
    """分析二进制文件，识别代码段和数据段"""
    md = Cs(cs_arch, cs_mode)
    md.detail = True

    text_start = None
    text_end = None
    data_start = None

    # 初始入口点
    entry_point = 0
    # 尝试偏移字节数
    offset_increment = 1
    # 最大尝试次数
    max_attempts = 32

    print(f"{YELLOW}[*]{END} Searching for segments, please be patient...")

    while entry_point < len(binary_data):
        instructions = list(md.disasm(binary_data[entry_point:], entry_point))
        if instructions:
            for i in instructions:
                if text_start is None:
                    text_start = i.address
                text_end = i.address + i.size
            # 重置尝试计数器
            max_attempts = 32
            # 移动到下一个指令的结束地址继续反汇编
            entry_point = text_end
        else:
            # 如果没有指令，尝试偏移一个字节
            entry_point += offset_increment
            max_attempts -= 1
            if max_attempts <= 0:
                print(f"{YELLOW}[*]{END} No more segments found after multiple attempts.")
                break

    # 识别数据段
    data_start = text_end if text_end else entry_point
    data_end = len(binary_data)

    print(f"{GREEN}[+]{END} Done!")
    return text_start, text_end, data_start, data_end

def get_elf_header(elf_arch, endian, entry_point, is_64_bit):
    """获取 ELF Header"""
    if is_64_bit:
        return struct.pack(
            '<16sHHIQQQIHHHHHH',
            b'\x7fELF' + bytes([2, endian, 1, 0, 0, 0, 0, 0, 0, 0, 0]),  # Magic number and other initial bytes
            2,                  # Type: Executable file
            elf_arch,           # Machine: from map
            1,                  # Version
            entry_point,        # Entry point address
            0x40,               # Start of program headers
            0,                  # Start of section headers
            0,                  # Flags
            0x40,               # Size of this header
            0x38,               # Size of program headers
            2,                  # Number of program headers
            0,                  # Size of section headers
            0,                  # Number of section headers
            0                   # Section header string table index
        )
    else:
        return struct.pack(
            '<16sHHIIIIIHHHHHH',
            b'\x7fELF' + bytes([1, endian, 1, 0, 0, 0, 0, 0, 0, 0, 0]),  # Magic number and other initial bytes
            2,                  # Type: Executable file
            elf_arch,           # Machine: from map
            1,                  # Version
            entry_point,        # Entry point address
            0x34,               # Start of program headers
            0,                  # Start of section headers
            0,                  # Flags
            0x34,               # Size of this header
            0x20,               # Size of program headers
            2,                  # Number of program headers
            0,                  # Size of section headers
            0,                  # Number of section headers
            0                   # Section header string table index
        )

def get_program_headers(rebase_text_start, rebase_data_start, text_size, data_size):
    """获取 Program Headers"""
    program_header_text = struct.pack(
        '<IIIIIIII',
        1,                  # Type: Loadable segment
        5,                  # Flags: Read, Execute
        0x0,                # Offset
        rebase_text_start,  # Virtual address
        rebase_text_start,  # Physical address
        text_size,          # Size in file
        text_size,          # Size in memory
        0x1000              # Align
    )

    program_header_data = struct.pack(
        '<IIIIIIII',
        1,                  # Type: Loadable segment
        6,                  # Flags: Read, Write
        text_size,          # Offset
        rebase_data_start,  # Virtual address
        rebase_data_start,  # Physical address
        data_size,          # Size in file
        data_size,          # Size in memory
        0x1000              # Align
    )

    return program_header_text, program_header_data

def get_section_headers():
    """获取 Section Headers"""
    # 节头部字符串表
    section_header_string_table = b'\x00.text\x00.data\x00'

    # 计算各个 section 的 size
    text_section_size = 0x1000
    data_section_size = 0x1000

    # Section Header: .text section
    section_header_text = struct.pack(
        '<IIIIIIIIII',
        len(b'.text') + 1,  # Section name (offset to string table)
        1,                 # Type: PROGBITS
        0x6,               # Flags: Executable
        0,                 # Address
        0,                 # Offset
        text_section_size, # Size
        0x10,              # Align
        0,                 # Link
        0,                 # Info
        0                  # Entry size
    )

    # Section Header: .data section
    section_header_data = struct.pack(
        '<IIIIIIIIII',
        len(b'.data') + 1,  # Section name (offset to string table)
        1,                 # Type: PROGBITS
        0x3,               # Flags: Writable
        0,                 # Address
        0,                 # Offset
        data_section_size, # Size
        0x10,              # Align
        0,                 # Link
        0,                 # Info
        0                  # Entry size
    )

    return section_header_text, section_header_data, section_header_string_table

def print_elf_header(elf_header, is_64_bit):
    """打印 ELF Header 信息"""
    elf_header_info = struct.unpack(
        '<16sHHIQQQIHHHHHH' if is_64_bit else '<16sHHIIIIIHHHHHH',
        elf_header
    )
    print("ELF Header:")
    print(f"  Magic:   {elf_header_info[0].hex()}")
    print(f"  Class:   {'64-bit' if is_64_bit else '32-bit'}")
    print(f"  Data:    {'little endian' if elf_header_info[2] == 1 else 'big endian'}")
    print(f"  Type:    {elf_header_info[1]}")
    print(f"  Machine: {elf_header_info[2]}")
    print(f"  Version: {elf_header_info[3]}")
    print(f"  Entry point address: 0x{elf_header_info[4]:x}")
    print(f"  Start of program headers: {elf_header_info[5]} bytes")
    print(f"  Start of section headers: {elf_header_info[6]} bytes")
    print(f"  Flags: {elf_header_info[7]}")
    print(f"  Size of this header: {elf_header_info[8]} bytes")
    print(f"  Size of program headers: {elf_header_info[9]} bytes")
    print(f"  Number of program headers: {elf_header_info[10]}")
    print(f"  Size of section headers: {elf_header_info[11]} bytes")
    print(f"  Number of section headers: {elf_header_info[12]}")
    print(f"  Section header string table index: {elf_header_info[13]}")

def main():
    firm, elf_arch, cs_arch, cs_mode, endian = get_arch_info()

    # 加载原始二进制文件
    binary_path = firm
    binary_data = open(binary_path, 'rb').read()

    # 分析二进制文件
    text_start, text_end, data_start, data_end = analyze_binary(binary_data, cs_arch, cs_mode)

    # 打印原始段信息
    print(f"Original .text segment: 0x{text_start:x} - 0x{text_end:x}")
    print(f"Original .data segment: 0x{data_start:x} - 0x{data_end:x}")

    # 计算重定位后的段地址
    original_base = 0
    rebase_address = 0x40205000
    rebase_text_start = text_start - original_base + rebase_address
    rebase_data_start = data_start - original_base + rebase_address

    # 打印重定位后的段信息
    print(f"Rebased .text segment: 0x{rebase_text_start:x} - 0x{rebase_text_start + (text_end - text_start):x}")
    print(f"Rebased .data segment: 0x{rebase_data_start:x} - 0x{rebase_data_start + (data_end - data_start):x}")

    # 获取 ELF Header 和 Program Headers
    is_64_bit = elf_arch in [0x3E, 0xB7, 0x08]
    elf_header = get_elf_header(elf_arch, endian, rebase_address, is_64_bit)
    program_header_text, program_header_data = get_program_headers(rebase_text_start, rebase_data_start, text_end - text_start, data_end - data_start)
    section_header_text, section_header_data, section_header_str_table = get_section_headers()

    # 打印 ELF Header 信息
    print_elf_header(elf_header, is_64_bit)

    # 生成 output.elf 文件
    with open('output.elf', 'wb') as f:
        f.write(elf_header)
        f.write(program_header_text)
        f.write(program_header_data)
        f.write(section_header_text)
        f.write(section_header_data)
        f.write(section_header_str_table)
        f.write(binary_data)
    print(f"{GREEN}[+]{END} ELF file saved as output.elf")

if __name__ == "__main__":
    main()

