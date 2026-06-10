#!/usr/bin/env python3

import argparse
import rulelib
import sys
import re
import json
import ipaddress
import dataclasses
from pathlib import Path
from collections import defaultdict


COMMENT_PATTERN = re.compile(r"(?<!:)//.*$")


RULE_TYPE_ORDER = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP"
]
RULE_TYPE_EXTRA = {"USER-AGENT", "URL-REGEX", "PROTOCOL", "PROCESS-NAME"}
RULE_TYPE_INDEX = {rule: index for index, rule in enumerate(RULE_TYPE_ORDER)}
RULE_TYPE_KNOWN = frozenset(RULE_TYPE_ORDER) | RULE_TYPE_EXTRA


EGERN_RULE_MAP = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-WILDCARD": "domain_wildcard_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set",
    "IP-ASN": "asn_set",
    "GEOIP": "geoip_set"
}
EGERN_RULE_QUOTE = {"domain_wildcard_set"}


QUANTUMULTX_RULE_MAP = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "DOMAIN-WILDCARD": "HOST-WILDCARD",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP6-CIDR",
    "IP-ASN": "IP-ASN",
    "GEOIP": "GEOIP"
}


SINGBOX_RULE_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr"
}


STASH_DOMAIN_FILE = {"AdBlock", "Advertising", "DIRECT", "GreatFireWall", "PROXY", "REJECT"}
STASH_IPCIDR_FILE = {"CNCIDR", "CNCIDR4", "CNCIDR6"}


@dataclasses.dataclass
class Rule:
    type: str; value: str; param: str = ""
@dataclasses.dataclass
class RuleSet:
    name: str; rules: list = dataclasses.field(default_factory=list)


def process_parse(line, enable_type=False, enable_param=False):
    line = COMMENT_PATTERN.sub("", line).strip()
    if not line or line.startswith("#"):
        return None
    rule_type, rule_value, rule_param = (line.split(",", 2) + ["", ""])[:3]
    if enable_type and rule_type.upper() not in RULE_TYPE_KNOWN:
        if rule_value and not rule_param:
            rule_param, rule_value = rule_value, ""
        try:
            rule_value = ipaddress.ip_network(rule_type, strict=False)
            rule_type = "IP-CIDR6" if rule_value.version == 6 else "IP-CIDR"
        except ValueError:
            rule_value = rule_type.lstrip(".")
            rule_type = "DOMAIN-SUFFIX" if rule_type.startswith(".") else "DOMAIN"
    rule_type, rule_value, rule_param = rule_type.upper(), str(rule_value), rule_param.strip()
    if enable_param and rule_type in {"IP-CIDR", "IP-CIDR6"}:
        param = [item.strip() for item in rule_param.split(",") if item.strip()]
        if "no-resolve" not in param:
            param.append("no-resolve")
        rule_param = ",".join(param)
    return Rule(rule_type, rule_value, rule_param)


def process_order(rules, unknown_rule=False):
    seen, result = set(), []
    def rule_sort(rule):
        return (RULE_TYPE_INDEX.get(rule.type, len(RULE_TYPE_ORDER)), rule.value)
    for rule in sorted(rules, key=rule_sort):
        rule_data = (rule.type.lower(), rule.value.lower())
        if rule_data in seen:
            continue
        if rule.type not in RULE_TYPE_INDEX and not unknown_rule:
            continue
        seen.add(rule_data)
        result.append(rule)
    return result


def process_read(file_path, enable_type=False, enable_order=False, enable_param=False, unknown_rule=False):
    rules = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        rule = process_parse(line, enable_type=enable_type, enable_param=enable_param)
        if rule:
            rules.append(rule)
    if enable_order:
        rules = process_order(rules, unknown_rule=unknown_rule)
    return RuleSet(file_path.stem, rules)


def process_write(file_path, rule_name, rule_data, platform):
    def rule_total():
        if platform in {"Egern", "Stash"}:
            return sum(line.startswith("  - ") for line in rule_data)
        if platform in {"QuantumultX", "Surge"}:
            return len(rule_data)
        return 0
    with file_path.open("w", encoding="utf-8", newline="\n") as file:
        if platform == "Singbox":
            file.write(json.dumps(rule_data, indent=2, ensure_ascii=False) + "\n")
        else:
            file.write(f"# 规则名称: {rule_name}\n")
            file.write(f"# 规则统计: {rule_total()}\n\n")
            file.writelines(f"{line}\n" for line in rule_data)
    print(f"Processed ({platform}): {file_path}")


def convert_rules(ruleset, platform):
    rule_list, rule_name = ruleset.rules, ruleset.name
    if platform == "Egern":
        rule_dict = defaultdict(list)
        no_resolve = any(rule.param == "no-resolve" for rule in rule_list)
        for rule in rule_list:
            if rule.type in EGERN_RULE_MAP:
                rule_type = EGERN_RULE_MAP[rule.type]
                rule_value = f"'{rule.value}'" if rule_type in EGERN_RULE_QUOTE else rule.value
                rule_dict[rule_type].append(rule_value)
        output = ["no_resolve: true"] if no_resolve else []
        for rule_type, rule_data in rule_dict.items():
            output.append(f"{rule_type}:")
            output.extend(f"  - {rule_value}" for rule_value in rule_data)
        return output
    elif platform == "QuantumultX":
        output = []
        for rule in rule_list:
            if rule.type in QUANTUMULTX_RULE_MAP:
                rule_type = QUANTUMULTX_RULE_MAP[rule.type]
                output.append(f"{rule_type},{rule.value},{rule_name}")
        return output
    elif platform == "Singbox":
        rule_dict = defaultdict(list)
        for rule in rule_list:
            if rule.type in SINGBOX_RULE_MAP:
                rule_type = SINGBOX_RULE_MAP[rule.type]
                rule_dict[rule_type].append(rule.value)
        rule_data = [{rule_type: rule_value} for rule_type, rule_value in rule_dict.items()]
        output = {"version": 3, "rules": rule_data}
        return output
    elif platform == "Stash":
        output = ["payload:"]
        for rule in rule_list:
            if rule_name in STASH_DOMAIN_FILE:
                rule_value = f"+.{rule.value}" if rule.type == "DOMAIN-SUFFIX" else rule.value
                output.append(f"  - '{rule_value}'")
            elif rule_name in STASH_IPCIDR_FILE:
                output.append(f"  - '{rule.value}'")
            else:
                rule_data = f"{rule.type},{rule.value}" + (f",{rule.param}" if rule.param else "")
                output.append(f"  - {rule_data}")
        return output
    elif platform == "Surge":
        output = []
        for rule in rule_list:
            rule_data = f"{rule.type},{rule.value}" + (f",{rule.param}" if rule.param else "")
            output.append(rule_data)
        return output
    sys.exit(f"Unknown Platform: {platform}")


def capture_file(file_path, platform):
    if not file_path.exists():
        sys.exit(f"{file_path} Not Found.")
    if file_path.is_file():
        if platform == "Singbox" and file_path.suffix != ".json":
            sys.exit(f"Singbox only supports JSON File: {file_path.suffix}")
        return [file_path]
    if not file_path.is_dir():
        sys.exit(f"{file_path} Unknown Type.")
    file_list = [path for path in file_path.iterdir() if path.is_file()]
    if platform == "Singbox":
        file_list = [path for path in file_list if path.suffix == ".json"]
    file_list.sort()
    if not file_list:
        sys.exit(f"No File Found in: {file_path}")
    return file_list


def process_file(file_list, args):
    for file_path in file_list:
        try:
            rule_read = process_read(
                file_path, enable_type=args.type, enable_order=args.order,
                enable_param=args.param, unknown_rule=args.unknown_rule)
            rule_data = convert_rules(rule_read, args.platform)
            process_write(file_path, rule_read.name, rule_data, args.platform)
        except Exception as error:
            print(f"Failed to process {file_path}: {error}")
    print("Processed Completed.")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    ruleset = subparsers.add_parser("R") # R = Ruleset
    ruleset.add_argument("repo", nargs="?", help="Repository Name")
    sources = ruleset.add_mutually_exclusive_group(required=True)
    sources.add_argument("--download", action="store_true")
    sources.add_argument("--copy", action="store_true")
    convert = subparsers.add_parser("C") # C = Convert
    convert.add_argument("platform", choices=["Egern", "QuantumultX", "Singbox", "Stash", "Surge"])
    convert.add_argument("file_path", type=Path)
    convert.add_argument("--type", action=argparse.BooleanOptionalAction)
    convert.add_argument("--param", action=argparse.BooleanOptionalAction)
    convert.add_argument("--order", action=argparse.BooleanOptionalAction)
    convert.add_argument("--unknown-rule", action=argparse.BooleanOptionalAction)
    return parser.parse_args()

"""
def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    parser.add_argument("platform", choices=["Egern", "QuantumultX", "Singbox", "Stash", "Surge"])
    parser.add_argument("file_path", type=Path)
    parser.add_argument("--type", action=argparse.BooleanOptionalAction)
    parser.add_argument("--param", action=argparse.BooleanOptionalAction)
    parser.add_argument("--order", action=argparse.BooleanOptionalAction)
    parser.add_argument("--unknown-rule", action=argparse.BooleanOptionalAction)
    return parser.parse_args()


def main():
    args = parse_arguments()
    print("============== Build.py ==============")
    print(f"添加规则类型: {'已启用' if args.type else '未启用'}")
    print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
    print(f"排序规则去重: {'已启用' if args.order else '未启用'}")
    print(f"未知规则保留: {'已启用' if args.unknown_rule else '未启用'}")
    print("======================================")
    file = capture_file(args.file_path, args.platform)
    print(f"Platform: {args.platform}")
    print(f"Processed {len(file)} file(s) in: {args.file_path}")
    process_file(file, args)


if __name__ == "__main__":
    main()
"""

def rulelib_mode(args):
    print("============== Build.py ==============")
    print(f"使用下载规则: {'已启用' if args.download else '未启用'}")
    print(f"使用复制规则: {'已启用' if args.copy else '未启用'}")
    print("======================================")
    mode = "download" if args.download else "copy"
    rulelib.process_repo(mode, args.repo)


def convert_mode(args):
    print("============== Build.py ==============")
    print(f"添加规则类型: {'已启用' if args.type else '未启用'}")
    print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
    print(f"排序规则去重: {'已启用' if args.order else '未启用'}")
    print(f"未知规则保留: {'已启用' if args.unknown_rule else '未启用'}")
    print("======================================")
    file = capture_file(args.file_path, args.platform)
    print(f"Platform: {args.platform}")
    print(f"Processed {len(file)} file(s) in: {args.file_path}")
    process_file(file, args)


def main():
    args = parse_arguments()
    if args.mode == "R":
        rulelib_mode(args)
    elif args.mode == "C":
        convert_mode(args)


if __name__ == "__main__":
    main()