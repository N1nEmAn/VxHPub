#! /usr/bin/python3
# deal with Minifs for TP-Link
from construct import Struct, Const, Int32ub, Bytes, Adapter, Enum, Switch, this, AdaptationError, Array
import lzma
import argparse
import typing
import itertools
import multiprocessing
import hashlib
import os

TOKEN_LENGTH = 2


class FileLzma2014Adapter(Adapter):
    def _decode(self, obj, context, path):
        raise AdaptationError("not implement")

    def _encode(self, obj, context, path):
        raise AdaptationError("not implement")


class FileLzmaAdapter(Adapter):
    def _decode(self, obj, context, path):
        return lzma.decompress(obj)

    def _encode(self, obj, context, path):
        raise AdaptationError("not implement")


FileCompressType = Enum(Int32ub, Raw=2, Lzma=0, Lzma2014=4)

MiniFsHeader = Struct(
    "signature" / Const(b"MINIFS".ljust(16, b"\x00")),
    "version" / Int32ub,
    "entryCount" / Int32ub,
    "dataSize" / Int32ub,
    "origSize" / Int32ub
)

FileEntry = Struct(
    "nameMd5" / Bytes(16),
    "size" / Int32ub,
    "offset" / Int32ub,
    "origSize" / Int32ub,
    "flag" / FileCompressType,
    "content" / Switch(this.flag, {
        "raw": Bytes(this.size),
        "Lzma": FileLzmaAdapter(Bytes(this.size)),
        "Lzma2014": FileLzma2014Adapter(Bytes(this.size))
    })
)

MiniFs = Struct(
    "head" / MiniFsHeader,
    "Files" / Array(this.head.entryCount, FileEntry)
)

path_ch_pool = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
               b"-./_"


def collection_token(data: bytes):
    now_token = []
    for ch in data:
        # if ch in path_ch_pool:
        if 97 <= (ch | 0x20) <= 122 or 48 <= ch < 57 or ch in b"-./_":
            now_token.append(ch)
        else:
            if len(now_token) >= TOKEN_LENGTH:
                # tokens.extend(token_split(now_token))
                yield bytes(now_token)
            now_token.clear()


def path_walker(root_dir):
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as fp:
                    data = fp.read()
                yield data


def firmware_parse(firmware_path):
    print("reading firmware")
    with open(firmware_path, 'rb') as fp:
        data: bytes = fp.read()
    data = data[data.index(b"MINIFS"):]
    print("parse minifs")
    minifs = MiniFs.parse(data)
    print(f"parse minifs success, {len(minifs.Files)} files")
    return minifs


class PathTree:
    def __init__(self, prefix: bytes):
        self.prefix = prefix
        self.child: typing.Dict[bytes, PathTree] = {}

    def add_to_tree(self, path):
        if not path:
            return
        if isinstance(path, bytes):
            assert path[0] == 47
            path = path.split(b"/")[1:]
        p = path.pop(0)
        if p in self.child:
            self.child[p].add_to_tree(path)
        else:
            node = PathTree(self.prefix + p + b"/")
            self.child[p] = node
            node.add_to_tree(path)

    def adj_path(self, path):
        if isinstance(path, bytes):
            assert path[0] == 47
            path = path.split(b"/")[1:]

        if len(path) == 1:
            if path[0] in self.child:
                del self.child[path[0]]
            return

        p = path.pop(0)
        if p in self.child:
            self.child[p].add_to_tree(path)
        else:
            node = PathTree(self.prefix + p + b"/")
            self.child[p] = node
            node.adj_path(path)

    def walk(self):
        yield self.prefix
        for p in self.child.values():
            yield from p.walk()


def file_match_gen(md5_list: list):
    def file_match(paths: typing.Iterable):
        find_list = {}
        i = 0
        for path in paths:
            i += 1
            if i % 0x10000 == 0:
                # print(hex(i))
                pass
            md = hashlib.md5(path)
            if md.digest() in md5_list:
                find_list[md.hexdigest()] = path
        return find_list

    return file_match


def subprocess_path_finder(args):
    md5_list: list = args[0]
    prefixs: list = args[1]
    tokens: typing.List[typing.List[bytes]] = args[2]
    thread_id = args[3]

    file_math = file_match_gen(md5_list)
    # path_iter = map(lambda x: os.path.abspath(os.path.join(*x)),
    #                 itertools.product(prefixs, itertools.chain.from_iterable(tokens)))
    path_iter = map(lambda x: os.path.abspath(b"".join(x)),
                    itertools.product(prefixs, itertools.chain.from_iterable(tokens)))
    result = file_math(itertools.islice(path_iter, thread_id, None, multiprocessing.cpu_count()))
    return result


def multiprocess_find(md5_list: list, prefixs: list, tokens: typing.List[typing.List[bytes]]):
    file_dict = {}
    with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
        for result in p.map(subprocess_path_finder,
                            map(lambda x: (md5_list, prefixs, tokens, x), range(multiprocessing.cpu_count()))):
            file_dict.update(result)
    return file_dict


def find_file_path(md5_list: list, tokens: typing.List[typing.List[bytes]]):
    # first find all tokens that like a path
    file_dict = {}
    path_tree = PathTree(b'/')

    p = filter(lambda x: b"/" in x, itertools.chain.from_iterable(tokens))
    p, p2 = itertools.tee(p, 2)

    # use all path to build a Trie
    for path in filter(os.path.isabs, p2):
        path_tree.add_to_tree(os.path.abspath(path))

    # 1. direct search all thing like path
    file_math = file_match_gen(md5_list)
    result = file_math(p)
    file_dict.update(result)
    for path in result.values():
        path_tree.adj_path(path)

    searched_set = set()
    while True:
        search_paths = [i for i in path_tree.walk() if i not in searched_set]
        result = multiprocess_find(md5_list, search_paths, tokens)
        if not result:
            return file_dict
        file_dict.update(result)
        for path in result.values():
            path_tree.adj_path(path)
        searched_set.update(search_paths)


def main():
    parse = argparse.ArgumentParser(description="extract file from TP-Link firmware")
    parse.add_argument("file", help="firmware file")
    parse.add_argument("-o", "--out", help="output put dir")
    parse.add_argument("-a", "--add", help="addition file for collection token")

    args = parse.parse_args()
    firmware_path = args.file
    assert os.path.isfile(firmware_path)
    if args.out is not None:
        out_dir = args.out
    else:
        out_dir = "./minifs"
    os.makedirs(out_dir, exist_ok=True)

    minifs = firmware_parse(firmware_path)

    if args.add is not None:
        addition_dir = args.add
    else:
        addition_dir = None
    firmware_tokens = map(lambda x: collection_token(x.content), minifs.Files)
    if addition_dir is not None:
        addition_tokens = map(lambda x: collection_token(x), path_walker(addition_dir))
        all_tokens = itertools.chain(firmware_tokens, addition_tokens)
    else:
        all_tokens = firmware_tokens
    md5_list = [file.nameMd5 for file in minifs.Files]
    all_tokens = [list(tokens) for tokens in all_tokens]

    # use prev result
    result = find_file_path(md5_list, all_tokens)
    # result = cache_result

    for file in minifs.Files:
        name_md5 = file.nameMd5.hex()
        if name_md5 in result:
            file_path = result[name_md5].decode()  # use str path
        else:
            file_path = name_md5
        file_path = os.path.join(out_dir, file_path[1:])  # strip /
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as fp:
            fp.write(file.content)


if __name__ == '__main__':
    main()
