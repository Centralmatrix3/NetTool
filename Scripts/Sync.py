#!/usr/bin/env python3

import argparse
import functools
import os
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

RULESET_SOURCE_URL = "https://raw.githubusercontent.com/Centralmatrix3/Network/master/Ruleset"
# ============================== #
# 读取规则内容
# ============================== #
@functools.cache
def read_rule(source):
    if urlsplit(source).scheme in {"http", "https"}:
        with urllib.request.urlopen(source, timeout=30) as response:
            return response.read().decode("utf-8").rstrip()
    return Path(source).read_text(encoding="utf-8").rstrip()
# ============================== #
# 写入规则内容
# ============================== #
def write_rule(target_file, source_file):
    source_contents = []
    for source in source_file:
        try:
            source_contents.append(read_rule(source))
            print(f"Processed: {source} -> {target_file}")
        except Exception as error:
            raise RuntimeError(f"Process Failed: {source} ({error})") from error
    target_path = Path(target_file)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8", newline="\n") as output:
        output.write("\n".join(source_contents) + "\n")
# ============================== #
# 解析规则路径
# ============================== #
def resolve_path(source_path, source_rule):
    source_path = source_path.rstrip("/")
    return [f"{source_path}/{file}" for file in source_rule]
# ============================== #
# 解析仓库名称
# ============================== #
def resolve_repo(repo_arg):
    if repo_arg := (repo_arg or "").strip():
        return repo_arg
    if env_repo := os.environ.get("GITHUB_REPOSITORY", "").strip():
        return env_repo.rsplit("/", 1)[-1]
    raise ValueError("No Repository Specified")
# ============================== #
# 构建仓库规则
# ============================== #
def process_rule(source_path, repository):
    print(f"Execute in {repository} Repository")
    if repository == "Network":
        rule_source_link = {
            "Ruleset/AI.list": [
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list",
                "https://raw.githubusercontent.com/ConnersHua/RuleGo/master/Surge/Ruleset/Extra/AI.list"
            ],
            "Ruleset/Global.list": [
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyGFWlist.list",
                "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/gfw.txt"
            ],
            "Ruleset/AdBlock.list": ["https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt"],
            "Ruleset/Adobe.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Adobe.list"],
            "Ruleset/Advertising.list": ["https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules.list"],
            "Ruleset/Alibaba.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Alibaba.list"],
            "Ruleset/Amazon.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Amazon.list"],
            "Ruleset/AmazonIP.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AmazonIp.list"],
            "Ruleset/Apple.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Apple.list"],
            "Ruleset/AppleTV.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AppleTV.list"],
            "Ruleset/BBC.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/BBCiPlayer.list"],
            "Ruleset/Baidu.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Baidu.list"],
            "Ruleset/BiliBili.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bilibili.list"],
            "Ruleset/Binance.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Binance.list"],
            "Ruleset/ByteDance.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ByteDance.list"],
            "Ruleset/CNCIDR.list": ["https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"],
            "Ruleset/China.list": ["https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China.list"],
            "Ruleset/ChinaASN.list": ["https://raw.githubusercontent.com/missuo/ASN-China/main/ASN.China.list"],
            "Ruleset/ChinaBGP.list": ["https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ChinaIPsBGP/ChinaIPsBGP.list"],
            "Ruleset/ChinaIP.list": ["https://raw.githubusercontent.com/missuo/ASN-China/main/IP.China.list"],
            "Ruleset/ChinaIPv4.list": ["https://raw.githubusercontent.com/missuo/ASN-China/main/IPv4.China.list"],
            "Ruleset/ChinaIPv6.list": ["https://raw.githubusercontent.com/missuo/ASN-China/main/IPv6.China.list"],
            "Ruleset/Crypto.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Crypto.list"],
            "Ruleset/DIRECT.list": ["https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt"],
            "Ruleset/Developer.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Developer.list"],
            "Ruleset/Disney.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/DisneyPlus.list"],
            "Ruleset/Docker.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Docker.list"],
            "Ruleset/Facebook.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Facebook.list"],
            "Ruleset/Gemini.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Gemini.list"],
            "Ruleset/GitHub.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Github.list"],
            "Ruleset/Google.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Google.list"],
            "Ruleset/GoogleCN.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleCN.list"],
            "Ruleset/HBO.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/HBO.list"],
            "Ruleset/HBOAsia.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/HBO_GO_HKG.list"],
            "Ruleset/Hulu.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Hulu.list"],
            "Ruleset/HuluJP.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/HuluJapan.list"],
            "Ruleset/IQiYi.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Iqiyi.list"],
            "Ruleset/Microsoft.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Microsoft.list"],
            "Ruleset/NetEase.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetEase.list"],
            "Ruleset/NetEaseMusic.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetEaseMusic.list"],
            "Ruleset/Netflix.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list"],
            "Ruleset/NetflixIP.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetflixIP.list"],
            "Ruleset/OneDrive.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OneDrive.list"],
            "Ruleset/PROXY.list": ["https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/proxy.txt"],
            "Ruleset/REJECT.list": ["https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt"],
            "Ruleset/Reddit.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Reddit.list"],
            "Ruleset/SINA.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Sina.list"],
            "Ruleset/Scholar.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Scholar.list"],
            "Ruleset/Spotify.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Spotify.list"],
            "Ruleset/Steam.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Steam.list"],
            "Ruleset/SteamCN.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list"],
            "Ruleset/Tencent.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Tencent.list"],
            "Ruleset/Twitter.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Twitter.list"],
            "Ruleset/USCIDR.list": ["https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/us.txt"],
            "Ruleset/WeChat.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Wechat.list"],
            "Ruleset/YouTube.list": ["https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list"],
            "Ruleset/iCloud.list": ["https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/icloud.txt"]
        }
        rule_source_file = {
            "AdBlock": ["AdBlock.list"],
            "Advertising": ["Advertising.list"],
            "AppStore": ["AppStore.list"],
            "Apple": ["Apple.list"],
            "BiliBili": ["BiliBili.list"],
            "ChinaASN": ["ChinaASN.list"],
            "ChinaMedia": ["ChinaMedia.list"],
            "DouYin": ["DouYin.list"],
            "GEOIPCN": ["GEOIPCN.list"],
            "GitHub": ["GitHub.list"],
            "Global": ["Global.list"],
            "GlobalMedia": ["GlobalMedia.list"],
            "Google": ["Google.list"],
            "HMTMedia": ["HMTMedia.list"],
            "LAN": ["LAN.list"],
            "Microsoft": ["Microsoft.list"],
            "Telegram": ["Telegram.list"],
            "TikTok": ["TikTok.list"],
            "Unbreak": ["Unbreak.list"],
            "WeChat": ["WeChat.list"]
        }
        platform_config = {
            "QuantumultX": {"extension": "list", "exclude": set()},
            "Stash": {"extension": "yaml", "exclude": set()},
            "Surge": {"extension": "list", "exclude": set()}
        }
    elif repository == "Matrix-io":
        rule_source_link = {}
        rule_source_file = {
            "5iTV": ["5iTV.list"],
            "ABC": ["ABC.list"],
            "AMAP": ["AMAP.list"],
            "Abema": ["Abema.list"],
            "AcFun": ["AcFun.list"],
            "AdBlock": ["AdBlock.list"],
            "Advertising": ["Advertising.list"],
            "Akamai": ["Akamai.list"],
            "AliPay": ["AliPay.list"],
            "Alibaba": ["Alibaba.list"],
            "All4": ["All4.list"],
            "Amazon": ["Amazon.list"],
            "Android": ["Android.list"],
            "AppStore": ["AppStore.list"],
            "Apple": ["Apple.list"],
            "AppleTV": ["AppleTV.list"],
            "Baidu": ["Baidu.list"],
            "BiliBili": ["BiliBili.list"],
            "Blizzard": ["Blizzard.list"],
            "ByteDance": ["ByteDance.list"],
            "ChinaASN": ["ChinaASN.list"],
            "ChinaBGP": ["ChinaBGP.list"],
            "ChinaIP": ["ChinaIP.list"],
            "ChinaIPv4": ["ChinaIPv4.list"],
            "ChinaIPv6": ["ChinaIPv6.list"],
            "ChinaMedia": ["ChinaMedia.list"],
            "Claude": ["Claude.list"],
            "Coolapk": ["Coolapk.list"],
            "DIRECT": ["DIRECT.list"],
            "Deezer": ["Deezer.list"],
            "Discord": ["Discord.list"],
            "Discovery": ["Discovery.list"],
            "Disney": ["Disney.list"],
            "Docker": ["Docker.list"],
            "DouBan": ["DouBan.list"],
            "DouYin": ["DouYin.list"],
            "DouYu": ["DouYu.list"],
            "Dropbox": ["Dropbox.list"],
            "EncoreTVB": ["EncoreTVB.list"],
            "Facebook": ["Facebook.list"],
            "GEOIPCN": ["GEOIPCN.list"],
            "Gemini": ["Gemini.list"],
            "GitHub": ["GitHub.list"],
            "GitLab": ["GitLab.list"],
            "Global": ["Global.list"],
            "GlobalMedia": ["GlobalMedia.list"],
            "Google": ["Google.list"],
            "GoogleCN": ["GoogleCN.list"],
            "HBO": ["HBO.list"],
            "HBOAsia": ["HBOAsia.list"],
            "HMTMedia": ["HMTMedia.list"],
            "Heroku": ["Heroku.list"],
            "HuYa": ["HuYa.list"],
            "Hulu": ["Hulu.list"],
            "HuluJP": ["HuluJP.list"],
            "IQiYi": ["IQiYi.list"],
            "JOOX": ["JOOX.list"],
            "KKBOX": ["KKBOX.list"],
            "KKTV": ["KKTV.list"],
            "LAN": ["LAN.list"],
            "Microsoft": ["Microsoft.list"],
            "Mozilla": ["Mozilla.list"],
            "MyTVSuper": ["MyTVSuper.list"],
            "NetEase": ["NetEase.list"],
            "NetEaseMusic": ["NetEaseMusic.list"],
            "Netflix": ["Netflix.list"],
            "Niconico": ["Niconico.list"],
            "NivodTV": ["NivodTV.list"],
            "Notion": ["Notion.list"],
            "Olevod": ["Olevod.list"],
            "OneDrive": ["OneDrive.list"],
            "OpenAI": ["OpenAI.list"],
            "Oracle": ["Oracle.list"],
            "PPVideo": ["PPVideo.list"],
            "PROXY": ["PROXY.list"],
            "PayPal": ["PayPal.list"],
            "PikPak": ["PikPak.list"],
            "PornHub": ["PornHub.list"],
            "PrimeVideo": ["PrimeVideo.list"],
            "Qobuz": ["Qobuz.list"],
            "Quark": ["Quark.list"],
            "Quora": ["Quora.list"],
            "REJECT": ["REJECT.list"],
            "RedBook": ["RedBook.list"],
            "SoundCloud": ["SoundCloud.list"],
            "Speedtest": ["Speedtest.list"],
            "Spotify": ["Spotify.list"],
            "Steam": ["Steam.list"],
            "SteamCN": ["SteamCN.list"],
            "TIDAL": ["TIDAL.list"],
            "TapTap": ["TapTap.list"],
            "Telegram": ["Telegram.list"],
            "Tencent": ["Tencent.list"],
            "TeraBox": ["TeraBox.list"],
            "TikTok": ["TikTok.list"],
            "Twitch": ["Twitch.list"],
            "Twitter": ["Twitter.list"],
            "Unbreak": ["Unbreak.list"],
            "Vercel": ["Vercel.list"],
            "ViuTV": ["ViuTV.list"],
            "WeChat": ["WeChat.list"],
            "WeiBo": ["WeiBo.list"],
            "WhatsApp": ["WhatsApp.list"],
            "Wikimedia": ["Wikimedia.list"],
            "Ximalaya": ["Ximalaya.list"],
            "Yandex": ["Yandex.list"],
            "YouTube": ["YouTube.list"],
            "Youku": ["Youku.list"],
            "Z-Library": ["Z-Library.list"],
            "iCloud": ["iCloud.list"],
        }
        platform_config = {
            "Clash": {"extension": "yaml", "exclude": set()},
            "Egern": {"extension": "yaml", "exclude": set()},
            "Loon": {"extension": "list", "exclude": set()},
            "QuantumultX": {"extension": "list", "exclude": set()},
            "Shadowrocket": {"extension": "list", "exclude": set()},
            "Sing-box": {"extension": "json", "exclude": {"ChinaASN", "GEOIPCN"}},
            "Stash": {"extension": "yaml", "exclude": set()},
            "Surge": {"extension": "list", "exclude": set()}
        }
    else:
        raise ValueError(f"Unknown Repository: {repository}")
    for target_file, source_file in rule_source_link.items():
        write_rule(target_file, source_file)
    for target_rule, source_rule in rule_source_file.items():
        source_file = resolve_path(source_path, source_rule)
        for platform, config in platform_config.items():
            if target_rule in config["exclude"]:
                print(f"Exclude {target_rule} for {platform}")
                continue
            target_file = f"Ruleset/{platform}/{target_rule}.{config['extension']}"
            write_rule(target_file, source_file)
    print(f"{repository} Repository: All Ruleset Processed!")
# ============================== #
# 处理仓库规则
# ============================== #
def process_repo(mode, repo=None):
    if mode not in {"download", "copy"}:
        raise ValueError(f"Unknown Mode: {mode}")
    repository = resolve_repo(repo)
    if mode == "download":
        source_path = RULESET_SOURCE_URL
    elif repository == "Network":
        source_path = "Ruleset"
    else:
        source_path = "Network/Ruleset"
    process_rule(source_path, repository)
# ============================== #
# 解析命令参数
# ============================== #
def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    parser.add_argument("repo", nargs="?")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--download", dest="mode", action="store_const", const="download")
    group.add_argument("--copy", dest="mode", action="store_const", const="copy")
    return parser.parse_args()
# ============================== #
# 程序入口
# ============================== #
def main():
    try:
        args = parse_arguments()
        print("============== Build.py ==============")
        print(f"使用下载规则: {'已启用' if args.mode == 'download' else '未启用'}")
        print(f"使用复制规则: {'已启用' if args.mode == 'copy' else '未启用'}")
        print("======================================")
        process_repo(args.mode, args.repo)
    except Exception as error:
        sys.exit(error)

if __name__ == "__main__":
    main()
