#!/usr/bin/env python3

import argparse
import dataclasses
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

COMMENT_PATTERN = re.compile(r"(?<!:)//.*$|#.*$")

EGERN_QUOTED_TYPE = {"DOMAIN-WILDCARD", "IP-ASN", "USER-AGENT", "URL-REGEX"}

RULE_TYPE_MAPPING = {
    "DOMAIN": {
        "Egern": "domain_set",
        "QuantumultX": "HOST",
        "Singbox": "domain",
        "Stash": "DOMAIN",
        "Surge": "DOMAIN"
    },
    "DOMAIN-SUFFIX": {
        "Egern": "domain_suffix_set",
        "QuantumultX": "HOST-SUFFIX",
        "Singbox": "domain_suffix",
        "Stash": "DOMAIN-SUFFIX",
        "Surge": "DOMAIN-SUFFIX"
    },
    "DOMAIN-KEYWORD": {
        "Egern": "domain_keyword_set",
        "QuantumultX": "HOST-KEYWORD",
        "Singbox": "domain_keyword",
        "Stash": "DOMAIN-KEYWORD",
        "Surge": "DOMAIN-KEYWORD"
    },
    "DOMAIN-WILDCARD": {
        "Egern": "domain_wildcard_set",
        "QuantumultX": "HOST-WILDCARD",
        "Stash": "DOMAIN-WILDCARD",
        "Surge": "DOMAIN-WILDCARD"
    },
    "IP-CIDR": {
        "Egern": "ip_cidr_set",
        "QuantumultX": "IP-CIDR",
        "Singbox": "ip_cidr",
        "Stash": "IP-CIDR",
        "Surge": "IP-CIDR"
    },
    "IP-CIDR6": {
        "Egern": "ip_cidr6_set",
        "QuantumultX": "IP6-CIDR",
        "Singbox": "ip_cidr",
        "Stash": "IP-CIDR6",
        "Surge": "IP-CIDR6"
    },
    "IP-ASN": {
        "Egern": "asn_set",
        "QuantumultX": "IP-ASN",
        "Stash": "IP-ASN",
        "Surge": "IP-ASN"
    },
    "GEOIP": {
        "Egern": "geoip_set",
        "QuantumultX": "GEOIP",
        "Stash": "GEOIP",
        "Surge": "GEOIP"
    },
    "USER-AGENT": {
        "Egern": "user_agent_set",
        "QuantumultX": "USER-AGENT",
        "Stash": "USER-AGENT",
        "Surge": "USER-AGENT"
    },
    "URL-REGEX": {
        "Egern": "url_regex_set",
        "Stash": "URL-REGEX",
        "Surge": "URL-REGEX"
    },
    "PROTOCOL": {
        "Egern": "protocol_set",
        "Stash": "PROTOCOL",
        "Surge": "PROTOCOL"
    },
    "PROCESS-NAME": {
        "Singbox": "process_name",
        "Stash": "PROCESS-NAME",
        "Surge": "PROCESS-NAME"
    }
}
# ==================== #
@dataclasses.dataclass(slots=True)
class Rule:
    type: str
    value: str = ""
    param: str = ""

@dataclasses.dataclass(slots=True)
class RuleSet:
    name: str
    rules: list[Rule]
    @property
    def total(self):
        return len(self.rules)
# ==================== #
def read_content(file_path, source_platform):
    with file_path.open("r", encoding="utf-8") as file:
        if source_platform == "Singbox":
            return json.load(file)
        content = []
        for line in file:
            line = COMMENT_PATTERN.sub("", line).strip()
            if line:
                content.append(line)
    return content

def write_content(file_path, ruleset, content, target_platform):
    with file_path.open("w", encoding="utf-8", newline="\n") as file:
        if target_platform == "Singbox":
            json.dump(content, file, indent=2, ensure_ascii=False)
            file.write("\n")
        else:
            file.write(f"# 规则名称: {ruleset.name}\n")
            file.write(f"# 规则统计: {ruleset.total}\n\n")
            file.writelines(f"{line}\n" for line in content)
    print(f"Processed ({target_platform}): {file_path}")
# ==================== #
def resolve_rules(file_path, source_platform):
    content = read_content(file_path, source_platform)
    type_mapping = {}
    for rule_type, platforms in RULE_TYPE_MAPPING.items():
        if platform_type := platforms.get(source_platform):
            type_mapping[platform_type] = rule_type
    if source_platform == "Egern":
        rules, rule_type, rule_param = [], "", ""
        for line in content:
            if line == "no_resolve: true":
                rule_param = "no-resolve"
                continue
            if line.endswith(":"):
                platform_type = line[:-1]
                rule_type = type_mapping.get(platform_type, platform_type)
                continue
            if line.startswith("- "):
                rule = Rule(rule_type, line[2:].strip("'\""))
                if rule_type in {"IP-CIDR", "IP-CIDR6"}:
                    rule.param = rule_param
                rules.append(rule)
        return RuleSet(file_path.stem, rules)
    if source_platform == "QuantumultX":
        rules = []
        for line in content:
            rule = Rule(*map(str.strip, line.split(",", 2)[:2]))
            rule.type = type_mapping.get(rule.type, rule.type)
            rules.append(rule)
        return RuleSet(file_path.stem, rules)
    if source_platform == "Singbox":
        rules = []
        for rule_group in content["rules"]:
            for platform_type, rule_values in rule_group.items():
                rule_type = type_mapping.get(platform_type, platform_type)
                for rule_value in rule_values:
                    rule = Rule(rule_type, rule_value)
                    if platform_type == "ip_cidr":
                        rule_cidr = ipaddress.ip_network(rule_value, strict=False)
                        rule.type = "IP-CIDR6" if rule_cidr.version == 6 else "IP-CIDR"
                        rule.value = str(rule_cidr)
                    rules.append(rule)
        return RuleSet(file_path.stem, rules)
    if source_platform == "Stash":
        rules = []
        for line in content:
            if not line.startswith("- "):
                continue
            line = line[2:].strip("'\"")
            if "," not in line:
                if line.startswith(("+.", "*.")):
                    line = line[1:]
                rules.append(Rule(line))
                continue
            rule = Rule(*map(str.strip, line.split(",", 2)))
            rule.type = type_mapping.get(rule.type, rule.type)
            rules.append(rule)
        return RuleSet(file_path.stem, rules)
    if source_platform == "Surge":
        rules = []
        for line in content:
            rule = Rule(*map(str.strip, line.split(",", 2)))
            rule.type = type_mapping.get(rule.type, rule.type)
            rules.append(rule)
        return RuleSet(file_path.stem, rules)
    raise ValueError(f"Unknown Source Platform: {source_platform}")
# ==================== #
def process_rules(ruleset, args):
    def apply_type(rules):
        for rule in rules:
            if rule.type.upper() in RULE_TYPE_MAPPING or rule.value:
                continue
            try:
                rule_cidr = ipaddress.ip_network(rule.type, strict=False)
                rule.value = str(rule_cidr)
                rule.type = "IP-CIDR6" if rule_cidr.version == 6 else "IP-CIDR"
            except ValueError:
                rule.value = rule.type.lstrip(".")
                rule.type = "DOMAIN-SUFFIX" if rule.type.startswith(".") else "DOMAIN"
        return rules
    def apply_exclude(rules):
        exclude = {"USER-AGENT", "URL-REGEX", "PROTOCOL", "PROCESS-NAME"}
        rules = [rule for rule in rules if rule.type not in exclude]
        return rules
    def apply_param(rules):
        for rule in rules:
            if rule.type in {"IP-CIDR", "IP-CIDR6"}:
                rule.param = "no-resolve"
        return rules
    def apply_order(rules):
        rule_dedup = {}
        for rule in rules:
            rule_dedup.setdefault((rule.type, rule.value.lower()), rule)
        type_order = {}
        for rule_type in RULE_TYPE_MAPPING:
            type_order[rule_type] = len(type_order)
        rules = sorted(
            rule_dedup.values(),
            key=lambda rule: (type_order.get(rule.type, len(type_order)), rule.value))
        return rules
    ruleset.rules = apply_type(ruleset.rules)
    if args.exclude:
        ruleset.rules = apply_exclude(ruleset.rules)
    if args.param:
        ruleset.rules = apply_param(ruleset.rules)
    if args.order:
        ruleset.rules = apply_order(ruleset.rules)
# ==================== #
def convert_rules(ruleset, target_platform):
    type_mapping = {}
    for rule_type, platforms in RULE_TYPE_MAPPING.items():
        if platform_type := platforms.get(target_platform):
            type_mapping[rule_type] = platform_type
    ruleset.rules = [rule for rule in ruleset.rules if rule.type in type_mapping]
    if target_platform == "Egern":
        rule_dict = defaultdict(list)
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            rule_value = f"'{rule.value}'" if rule.type in EGERN_QUOTED_TYPE else rule.value
            rule_dict[rule_type].append(rule_value)
        output = []
        if any(rule.param == "no-resolve" for rule in ruleset.rules):
            output.append("no_resolve: true")
        for rule_type, rule_values in rule_dict.items():
            output.append(f"{rule_type}:")
            output.extend(f"  - {rule_value}" for rule_value in rule_values)
        return output
    if target_platform == "QuantumultX":
        output = []
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            output.append(f"{rule_type},{rule.value},{ruleset.name}")
        return output
    if target_platform == "Singbox":
        rule_dict = defaultdict(list)
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            rule_dict[rule_type].append(rule.value)
        output = {"version": 3, "rules": [dict(rule_dict)] if rule_dict else []}
        return output
    if target_platform == "Stash":
        output, ruleset_types = ["payload:"], {rule.type for rule in ruleset.rules}
        if ruleset.total >= 5000 and ruleset_types <= {"DOMAIN", "DOMAIN-SUFFIX"}:
            for rule in ruleset.rules:
                rule_value = f"+.{rule.value}" if rule.type == "DOMAIN-SUFFIX" else rule.value
                output.append(f"  - '{rule_value}'")
            return output
        if ruleset.total >= 5000 and ruleset_types <= {"IP-CIDR", "IP-CIDR6"}:
            for rule in ruleset.rules:
                output.append(f"  - '{rule.value}'")
            return output
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            rule_line = f"{rule_type},{rule.value}" + (f",{rule.param}" if rule.param else "")
            output.append(f"  - {rule_line}")
        return output
    if target_platform == "Surge":
        output = []
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            rule_line = f"{rule_type},{rule.value}" + (f",{rule.param}" if rule.param else "")
            output.append(rule_line)
        return output
    raise ValueError(f"Unknown Target Platform: {target_platform}")
# ==================== #
def collect_files(file_paths, source_platform):
    file_list = []
    for path in file_paths:
        if not path.exists():
            raise FileNotFoundError(f"{path} Not Found.")
        if not path.is_file() and not path.is_dir():
            raise ValueError(f"{path} Unknown Type.")
        file_source = [path] if path.is_file() else path.iterdir()
        for file in file_source:
            if not file.is_file():
                continue
            if source_platform == "Singbox" and file.suffix.lower() != ".json":
                continue
            file_list.append(file)
    if not file_list:
        raise ValueError("No Supported File Found.")
    return sorted(file_list)

def process_files(file_paths, args):
    files = collect_files(file_paths, args.source_platform)
    failed_files = []
    print(f"Source Platform: {args.source_platform}")
    print(f"Target Platform: {args.target_platform}")
    print(f"Collected {len(files)} file(s) from {len(file_paths)} path(s)")
    for file in files:
        try:
            ruleset = resolve_rules(file, args.source_platform)
            process_rules(ruleset, args)
            content = convert_rules(ruleset, args.target_platform)
            write_content(file, ruleset, content, args.target_platform)
        except Exception as error:
            failed_files.append(file)
            print(f"Failed to process {file}: {error}")
    if failed_files:
        raise RuntimeError(f"Processed Failed: {len(failed_files)} file(s).")
    print("Processed Completed.")
# ==================== #
def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    platforms = ["Egern", "QuantumultX", "Singbox", "Stash", "Surge"]
    parser.add_argument("source_platform", choices=platforms)
    parser.add_argument("target_platform", choices=platforms)
    parser.add_argument("file_paths", type=Path, nargs="+")
    parser.add_argument("--exclude", action=argparse.BooleanOptionalAction)
    parser.add_argument("--param", action=argparse.BooleanOptionalAction)
    parser.add_argument("--order", action=argparse.BooleanOptionalAction)
    return parser.parse_args()
# ==================== #
def main():
    try:
        args = parse_arguments()
        print("============== Build.py ==============")
        print(f"来源规则平台: {args.source_platform}")
        print(f"目标规则平台: {args.target_platform}")
        print(f"排除规则类型: {'已启用' if args.exclude else '未启用'}")
        print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
        print(f"排序规则内容: {'已启用' if args.order else '未启用'}")
        print("======================================")
        process_files(args.file_paths, args)
    except Exception as error:
        sys.exit(error)

if __name__ == "__main__":
    main()
