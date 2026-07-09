#!/usr/bin/env python3
"""eShield GitHub Release 发布脚本。

用法：
    export GH_TOKEN=ghp_xxx          # Linux / Git Bash
    python3 scripts/publish-release.py

或 Windows PowerShell:
    $env:GH_TOKEN = "ghp_xxx"
    python scripts/publish-release.py

前置条件：
    1. 本地已打 tag 并推送到 origin：git push origin <TAG>
    2. 已设置 GH_TOKEN（Classic token，需要 repo 权限）
    3. 默认产物为 target/x86_64-unknown-linux-musl/release/eshield 和
       target/bpfel-unknown-none/release/eshield；也可通过 ASSET_DIR 环境变量指定目录
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = "BlkSword/eShield"


def current_version() -> str:
    """从 eshield/Cargo.toml 读取当前版本。"""
    import re

    text = Path("eshield/Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        print("错误：无法从 eshield/Cargo.toml 读取版本号")
        sys.exit(1)
    return m.group(1)


VERSION = current_version()
TAG = f"v{VERSION}"

# 默认产物目录：用户态 musl 二进制 + eBPF object
# 可通过环境变量 ASSET_DIR 覆盖
DEFAULT_ASSETS = [
    Path(f"target/x86_64-unknown-linux-musl/release/eshield"),
    Path(f"target/bpfel-unknown-none/release/eshield"),
]
ASSET_DIR = Path(os.environ.get("ASSET_DIR", ""))


def load_token() -> str:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print("错误：请先设置 GH_TOKEN 环境变量")
        print("示例：export GH_TOKEN=ghp_xxxxxxxxxxxx")
        sys.exit(1)
    return token


def api_request(url: str, method: str = "GET", data: bytes = None, headers: dict = None):
    """发送 GitHub API 请求，返回 (status_code, body_bytes)。"""
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.data = data
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check_existing_release(token: str) -> bool:
    url = f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}"
    status, _ = api_request(url, headers={"Authorization": f"token {token}"})
    return status == 200


def extract_changelog_body() -> str:
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    lines = changelog.splitlines()
    body_lines = []
    in_section = False
    for line in lines:
        if line.startswith(f"## {VERSION}"):
            in_section = True
            continue
        if line.startswith("## "):
            in_section = False
        if in_section:
            body_lines.append(line)
    body = "\n".join(body_lines).strip()
    if not body:
        body = f"eShield {TAG} release."
    return body


def create_release(token: str, body: str) -> str:
    url = f"https://api.github.com/repos/{REPO}/releases"
    payload = {
        "tag_name": TAG,
        "name": f"eShield {TAG}",
        "body": body,
        "draft": False,
        "prerelease": False,
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json; charset=utf-8",
    }
    status, resp = api_request(url, method="POST", data=data, headers=headers)
    if status != 201:
        print(f"创建 release 失败，HTTP {status}")
        print(resp.decode("utf-8", errors="replace"))
        sys.exit(1)
    release = json.loads(resp.decode("utf-8"))
    return release["upload_url"].replace("{?name,label}", "")


def upload_asset(token: str, upload_url: str, path: Path) -> bool:
    url = f"{upload_url}?name={path.name}"
    data = path.read_bytes()
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/octet-stream",
    }
    status, resp = api_request(url, method="POST", data=data, headers=headers)
    if status != 201:
        print(f"  [FAIL] {path.name} (HTTP {status})")
        print(resp.decode("utf-8", errors="replace"))
        return False
    print(f"  [OK] {path.name}")
    return True


def main():
    token = load_token()

    print(f"==> 检查 GitHub 上是否已存在 release {TAG}")
    if check_existing_release(token):
        print(f"错误：GitHub 上已存在 {TAG} release，请先删除或更换版本号")
        sys.exit(1)

    print(f"==> 从 CHANGELOG.md 提取 {TAG} 发布说明")
    body = extract_changelog_body()

    print(f"==> 创建 GitHub Release {TAG}")
    upload_url = create_release(token, body)

    print("==> 上传产物")
    assets: list[Path] = []
    if ASSET_DIR and ASSET_DIR.exists():
        assets = [f for f in sorted(ASSET_DIR.iterdir()) if f.is_file()]
    else:
        assets = [p for p in DEFAULT_ASSETS if p.exists()]

    if not assets:
        print("错误：未找到任何产物。请先生成 release 产物，或设置 ASSET_DIR 环境变量")
        print("默认产物：")
        for p in DEFAULT_ASSETS:
            print(f"  - {p}")
        sys.exit(1)

    for f in assets:
        upload_asset(token, upload_url, f)

    print("")
    print(f"==> 发布完成：https://github.com/{REPO}/releases/tag/{TAG}")


if __name__ == "__main__":
    main()
