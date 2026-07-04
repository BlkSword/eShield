#!/usr/bin/env python3
"""eShield GitHub Release 发布脚本。

用法：
    export GH_TOKEN=ghp_xxx          # Linux / Git Bash
    python3 scripts/publish-release.py

或 Windows PowerShell:
    $env:GH_TOKEN = "ghp_xxx"
    python scripts/publish-release.py

前置条件：
    1. 本地已打 tag 并推送到 origin：git push origin v0.3.1
    2. 已设置 GH_TOKEN（Classic token，需要 repo 权限）
    3. 产物已放在 ASSET_DIR 指定的目录中
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = "BlkSword/eShield"
TAG = "v0.3.1"
ASSET_DIR = Path("C:/Users/wfshenm/Downloads/118.193.35.84/202607041646")


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
        if line.startswith("## 0.3.1"):
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
        print(f"  ✗ {path.name} 上传失败 (HTTP {status})")
        print(resp.decode("utf-8", errors="replace"))
        return False
    print(f"  ✓ {path.name}")
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
    if not ASSET_DIR.exists():
        print(f"错误：产物目录不存在 {ASSET_DIR}")
        sys.exit(1)

    for f in sorted(ASSET_DIR.iterdir()):
        if f.is_file():
            upload_asset(token, upload_url, f)

    print("")
    print(f"==> 发布完成：https://github.com/{REPO}/releases/tag/{TAG}")


if __name__ == "__main__":
    main()
