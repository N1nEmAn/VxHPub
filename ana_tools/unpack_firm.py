import os
import lzma
import gzip
import bz2
import binwalk

# ANSI颜色代码
RED = '\033[91m'
GREEN = '\033[92m'
END = '\033[0m'
BLUE = '\033[34m'
YELLOW = '\033[93m'

def simplify_description(description):
    # 提取关键部分并替换特殊字符
    keywords = description.split(',')
    keywords = [kw.split(':')[0].strip() for kw in keywords]
    simplified_name = '_'.join(keywords).replace(' ', '_')
    # 进一步简化复杂模式
    simplified_name = simplified_name.replace('%', '').replace('.', '').replace('\"', '').replace('file_name', '')
    return simplified_name.strip('_')

def decompress_data(file_path, data, description):
    try:
        if 'lzma' in description.lower():
            return lzma.decompress(data)
        elif 'xz' in description.lower():
            return lzma.decompress(data)  # lzma可以解压xz格式
        elif 'gzip' in description.lower():
            return gzip.decompress(data)
        elif 'bzip2' in description.lower():
            return bz2.decompress(data)
        else:
            return None
    except lzma.LZMAError:
        return None
    except Exception:
        return None

def extract_and_decompress(file_path, processed_files):
    output_dir = "extracted"
    os.makedirs(output_dir, exist_ok=True)

    decompressed_files = []

    with open(file_path, 'rb') as f:
        file_data = f.read()

    results = list(binwalk.scan(file_path, signature=True, quiet=True))

    for module in results:
        for result in module.results:
            offset = result.offset
            description = simplify_description(result.description.lower())
            next_offset = None

            index = module.results.index(result)
            if index + 1 < len(module.results):
                next_offset = module.results[index + 1].offset
            else:
                next_offset = len(file_data)

            part_data = file_data[offset:next_offset]
            
            part_output_file = os.path.join(output_dir, f"{offset:08X}_{description}.bin")
            if part_output_file not in processed_files:
                try:
                    with open(part_output_file, 'wb') as out_f:
                        out_f.write(part_data)
                except Exception as e:
                    print(f"{RED}[-]{END} Failed to write part data to {part_output_file}: {e}")
                    continue

                decompressed_data = decompress_data(file_path, part_data, description)
                if decompressed_data:
                    decompressed_output_file = os.path.join(output_dir, f"{offset:08X}_{description}_decompressed.bin")
                    with open(decompressed_output_file, 'wb') as out_f:
                        out_f.write(decompressed_data)
                    
                    print(f"{GREEN}[+]{END} Decompressed data saved to {decompressed_output_file}")
                    decompressed_files.append(decompressed_output_file)

                processed_files.add(part_output_file)

    return decompressed_files

def unpack_lzma(firm_path):
    processed_files = set()
    files_to_process = [firm_path]

    while files_to_process:
        current_file = files_to_process.pop()
        print(f"{BLUE}[!]{END} Trying to unpack {current_file}")
        new_files = extract_and_decompress(current_file, processed_files)
        files_to_process.extend(new_files)

    decompressed_files = [os.path.join("extracted", f) for f in os.listdir("extracted")]

    # sum_file_path = os.path.join("./sum.bin")
    # with open(sum_file_path, 'wb') as sum_file:
    #     for decompressed_file in decompressed_files:
    #         with open(decompressed_file, 'rb') as df:
    #             sum_file.write(df.read())
    # print(f"{GREEN}[+]{END} Combined decompressed files into {sum_file_path}")

    print(f"{GREEN}[+]{END} Total successful decompressions: {len(decompressed_files)}")

if __name__ == "__main__":
    file_path = "wdr7660gv1-cn-up_2019-08-30_10.37.02.bin"
    unpack_lzma(file_path)

