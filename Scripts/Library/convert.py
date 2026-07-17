#!/usr/bin/env python3

import argparse
import dataclasses
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

STASH_DOMAIN_FILE = {"AdBlock", "Advertising", "DIRECT", "GreatFireWall", "PROXY", "REJECT"}
STASH_IPCIDR_FILE = {"CNCIDR", "CNCIDR4", "CNCIDR6"}

EGERN_QUOTED_TYPE = {"DOMAIN-WILDCARD"}

COMMENT_PATTERN = re.compile(r"(?<!:)//.*$")
DELIMIT_PATTERN = re.compile(r"\s*,\s*")

RULE_TYPE_MAPPING = {
    "DOMAIN": {
        "Egern": "domain_set",
        "QuantumultX": "HOST",
        "Singbox": "domain",
    },
    "DOMAIN-SUFFIX": {
        "Egern": "domain_suffix_set",
        "QuantumultX": "HOST-SUFFIX",
        "Singbox": "domain_suffix",
    },
    "DOMAIN-KEYWORD": {
        "Egern": "domain_keyword_set",
        "QuantumultX": "HOST-KEYWORD",
        "Singbox": "domain_keyword",
    },
    "DOMAIN-WILDCARD": {
        "Egern": "domain_wildcard_set",
        "QuantumultX": "HOST-WILDCARD",
    },
    "IP-CIDR": {
        "Egern": "ip_cidr_set",
        "QuantumultX": "IP-CIDR",
        "Singbox": "ip_cidr",
    },
    "IP-CIDR6": {
        "Egern": "ip_cidr6_set",
        "QuantumultX": "IP6-CIDR",
        "Singbox": "ip_cidr",
    },
    "IP-ASN": {
        "Egern": "asn_set",
        "QuantumultX": "IP-ASN",
    },
    "GEOIP": {
        "Egern": "geoip_set",
        "QuantumultX": "GEOIP",
    },
    "USER-AGENT": {},
    "URL-REGEX": {},
    "PROTOCOL": {},
    "PROCESS-NAME": {}
}

@dataclasses.dataclass(slots=True)
class Rule:
    type: str; value: str; param: str = ""

@dataclasses.dataclass(slots=True)
class RuleSet:
    name: str; rules: list[Rule] = dataclasses.field(default_factory=list)

def process_parse(line, enable_type=False, enable_param=False):
    line = DELIMIT_PATTERN.sub(",", COMMENT_PATTERN.sub("", line)).strip()
    if not line or line.startswith("#"):
        return None
    rule_type, rule_value, rule_param = (line.split(",", 2) + ["", ""])[:3]
    if enable_type and rule_type.upper() not in RULE_TYPE_MAPPING:
        try:
            rule_value = ipaddress.ip_network(rule_type, strict=False)
            rule_type = "IP-CIDR6" if rule_value.version == 6 else "IP-CIDR"
        except ValueError:
            rule_value = rule_type.lstrip(".")
            rule_type = "DOMAIN-SUFFIX" if rule_type.startswith(".") else "DOMAIN"
    rule_type, rule_value = rule_type.upper(), str(rule_value)
    if enable_param and rule_type in {"IP-CIDR", "IP-CIDR6"}:
        param = rule_param.split(",") if rule_param else []
        if "no-resolve" not in param:
            param.append("no-resolve")
        rule_param = ",".join(param)
    return Rule(rule_type, rule_value, rule_param)

def process_order(rules):
    type_order = {}
    for standard_type, platform_type in RULE_TYPE_MAPPING.items():
        if platform_type:
            type_order[standard_type] = len(type_order)
    type_whole = len(type_order)
    rule_dedup = {}
    for rule in rules:
        dedup_key = (rule.type, rule.value.lower())
        if dedup_key not in rule_dedup:
            rule_dedup[dedup_key] = rule
    def rule_order(rule):
        rule_type_order = type_order.get(rule.type, type_whole)
        rule_value_order = rule.value
        return (rule_type_order, rule_value_order)
    return sorted(rule_dedup.values(), key=rule_order)

def process_read(file_path, enable_type=False, enable_param=False, enable_order=False, unknown_rule=False):
    rules = []
    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            rule = process_parse(line, enable_type=enable_type, enable_param=enable_param)
            if rule and (RULE_TYPE_MAPPING.get(rule.type) or unknown_rule):
                rules.append(rule)
    if enable_order:
        rules = process_order(rules)
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
            json.dump(rule_data, file, indent=2, ensure_ascii=False)
            file.write("\n")
        else:
            file.write(f"# 规则名称: {rule_name}\n")
            file.write(f"# 规则统计: {rule_total()}\n\n")
            file.writelines(f"{line}\n" for line in rule_data)
    print(f"Processed ({platform}): {file_path}")

def process_rule(ruleset, platform):
    rule_list, rule_name = ruleset.rules, ruleset.name
    if platform == "Egern":
        rule_dict = defaultdict(list)
        no_resolve = False
        for rule in rule_list:
            if rule.param == "no-resolve":
                no_resolve = True
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if rule_type:
                rule_value = f"'{rule.value}'" if rule.type in EGERN_QUOTED_TYPE else rule.value
                rule_dict[rule_type].append(rule_value)
        output = ["no_resolve: true"] if no_resolve else []
        for rule_type, rule_group in rule_dict.items():
            output.append(f"{rule_type}:")
            output.extend(f"  - {rule_value}" for rule_value in rule_group)
        return output
    elif platform == "QuantumultX":
        output = []
        for rule in rule_list:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if rule_type:
                output.append(f"{rule_type},{rule.value},{rule_name}")
        return output
    elif platform == "Singbox":
        rule_dict = defaultdict(list)
        for rule in rule_list:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if rule_type:
                rule_dict[rule_type].append(rule.value)
        output = {"version": 3, "rules": [dict(rule_dict)] if rule_dict else []}
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
    raise ValueError(f"Unknown Platform: {platform}")

def collect_file(file_path, platform):
    file_list = []
    for path in file_path:
        if not path.exists():
            raise FileNotFoundError(f"{path} Not Found.")
        if not path.is_file() and not path.is_dir():
            raise ValueError(f"{path} Unknown Type.")
        file_source = [path] if path.is_file() else path.iterdir()
        for file in file_source:
            if not file.is_file():
                continue
            if platform == "Singbox" and file.suffix.lower() != ".json":
                continue
            file_list.append(file)
    file_list = sorted(file_list)
    if not file_list:
        raise ValueError("No Supported File Found.")
    return file_list

def process_file(file_path, args):
    file_list = collect_file(file_path, args.platform)
    process_failed_file = []
    print(f"Platform: {args.platform}")
    print(f"Processed {len(file_list)} file(s) from {len(file_path)} path(s)")
    for file in file_list:
        try:
            rule_read = process_read(file,
                enable_type=args.type, enable_order=args.order,
                enable_param=args.param, unknown_rule=args.unknown_rule)
            rule_data = process_rule(rule_read, args.platform)
            process_write(file, rule_read.name, rule_data, args.platform)
        except Exception as error:
            process_failed_file.append(file)
            print(f"Failed to process {file}: {error}")
    if process_failed_file:
        raise RuntimeError(f"Processed Failed: {len(process_failed_file)} file(s).")
    print("Processed Completed.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    parser.add_argument("platform", choices=["Egern", "QuantumultX", "Singbox", "Stash", "Surge"])
    parser.add_argument("file_path", type=Path, nargs="+")
    parser.add_argument("--type", action=argparse.BooleanOptionalAction)
    parser.add_argument("--param", action=argparse.BooleanOptionalAction)
    parser.add_argument("--order", action=argparse.BooleanOptionalAction)
    parser.add_argument("--unknown-rule", action=argparse.BooleanOptionalAction)
    return parser.parse_args()

def main():
    try:
        args = parse_arguments()
        print("============== Build.py ==============")
        print(f"添加规则类型: {'已启用' if args.type else '未启用'}")
        print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
        print(f"排序规则去重: {'已启用' if args.order else '未启用'}")
        print(f"未知规则保留: {'已启用' if args.unknown_rule else '未启用'}")
        print("======================================")
        process_file(args.file_path, args)
    except Exception as error:
        sys.exit(error)

if __name__ == "__main__":
    main()