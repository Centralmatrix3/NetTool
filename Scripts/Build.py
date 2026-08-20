#!/usr/bin/env python3

import argparse
from pathlib import Path
import Sync
import Convert

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    subparsers = parser.add_subparsers(dest="command", required=True)
    # Sync Source
    sync_parser = subparsers.add_parser("S")
    sync_parser.add_argument("repo", nargs="?")
    sync_source = sync_parser.add_mutually_exclusive_group(required=True)
    sync_source.add_argument("--download", dest="mode", action="store_const", const="download")
    sync_source.add_argument("--copy", dest="mode", action="store_const", const="copy")
    sync_parser.set_defaults(handler=sync_mode)
    # Convert Ruleset
    convert_parser = subparsers.add_parser("C")
    convert_parser.add_argument("platform", choices=["Egern", "QuantumultX", "Singbox", "Stash", "Surge"])
    convert_parser.add_argument("file_path", type=Path, nargs="+")
    convert_parser.add_argument("--type", action=argparse.BooleanOptionalAction)
    convert_parser.add_argument("--param", action=argparse.BooleanOptionalAction)
    convert_parser.add_argument("--order", action=argparse.BooleanOptionalAction)
    convert_parser.add_argument("--unknown-rule", action=argparse.BooleanOptionalAction)
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
    print(f"添加规则类型: {'已启用' if args.type else '未启用'}")
    print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
    print(f"排序规则去重: {'已启用' if args.order else '未启用'}")
    print(f"未知规则保留: {'已启用' if args.unknown_rule else '未启用'}")
    print("======================================")
    Convert.process_file(args.file_path, args)

def main():
    args = parse_arguments()
    args.handler(args)

if __name__ == "__main__":
    main()
