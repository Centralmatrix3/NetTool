#!/usr/bin/env python3

import argparse
from pathlib import Path
import Sync
import Convert

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    subparsers = parser.add_subparsers(dest="command", required=True)
    sync_parser = subparsers.add_parser("S")
    sync_parser.add_argument("repo", nargs="?")
    sync_source = sync_parser.add_mutually_exclusive_group(required=True)
    sync_source.add_argument("--download", dest="mode", action="store_const", const="download")
    sync_source.add_argument("--copy", dest="mode", action="store_const", const="copy")
    sync_parser.set_defaults(handler=sync_mode)
    convert_parser = subparsers.add_parser("C")
    platforms = ["Egern", "QuantumultX", "Singbox", "Stash", "Surge"]
    convert_parser.add_argument("source_platform", choices=platforms)
    convert_parser.add_argument("target_platform", choices=platforms)
    convert_parser.add_argument("file_paths", type=Path, nargs="+")
    convert_parser.add_argument("--exclude", action=argparse.BooleanOptionalAction)
    convert_parser.add_argument("--param", action=argparse.BooleanOptionalAction)
    convert_parser.add_argument("--order", action=argparse.BooleanOptionalAction)
    convert_parser.set_defaults(handler=convert_mode)
    return parser.parse_args()

def sync_mode(args):
    print("============== Build.py ==============")
    print(f"使用下载规则: {'已启用' if args.mode == 'download' else '未启用'}")
    print(f"使用复制规则: {'已启用' if args.mode == 'copy' else '未启用'}")
    print("======================================")
    Sync.process_repo(args.mode, args.repo)

def convert_mode(args):
    print("============== Build.py ==============")
    print(f"来源规则平台: {args.source_platform}")
    print(f"目标规则平台: {args.target_platform}")
    print(f"排除规则类型: {'已启用' if args.exclude else '未启用'}")
    print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
    print(f"排序规则内容: {'已启用' if args.order else '未启用'}")
    print("======================================")
    Convert.process_files(args.file_paths, args)

def main():
    args = parse_arguments()
    args.handler(args)

if __name__ == "__main__":
    main()
