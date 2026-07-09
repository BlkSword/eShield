#!/bin/bash
set -euo pipefail

# eShield GitHub Release 发布脚本
# 用法：
#   export GH_TOKEN=ghp_xxx
#   bash scripts/publish-release.sh
#
# 前置条件：
#   1. 本地已打 tag 并推送到 origin：git push origin <TAG>
#   2. 已设置 GH_TOKEN（Classic token，需要 repo 权限）
#   3. 默认产物为 target/x86_64-unknown-linux-musl/release/eshield 和
#      target/bpfel-unknown-none/release/eshield；也可通过 ASSET_DIR 环境变量指定目录

REPO="BlkSword/eShield"
VERSION=$(grep -m1 '^version' eshield/Cargo.toml | sed 's/.*"\([^"]*\)".*/\1/')
TAG="v${VERSION}"
DEFAULT_ASSETS=(
    "target/x86_64-unknown-linux-musl/release/eshield"
    "target/bpfel-unknown-none/release/eshield"
)
ASSET_DIR="${ASSET_DIR:-}"

if [ -z "${GH_TOKEN:-}" ]; then
    echo "错误：请先设置 GH_TOKEN 环境变量"
    echo "示例：export GH_TOKEN=ghp_xxxxxxxxxxxx"
    exit 1
fi

if ! git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "错误：本地不存在 tag $TAG"
    exit 1
fi

echo "==> 检查 GitHub 上是否已存在 release $TAG"
existing=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: token $GH_TOKEN" \
    "https://api.github.com/repos/$REPO/releases/tags/$TAG" || true)
if [ "$existing" = "200" ]; then
    echo "错误：GitHub 上已存在 $TAG release，请先删除或更换版本号"
    exit 1
fi

echo "==> 从 CHANGELOG.md 提取 $TAG 发布说明"
BODY=$(awk "/^## ${VERSION}/{flag=1;next}/^## /{flag=0}flag" CHANGELOG.md | sed 's/"/\\"/g' | awk '{printf "%s\\n", $0}')
if [ -z "$BODY" ]; then
    echo "警告：未从 CHANGELOG.md 提取到 $TAG 内容，使用默认说明"
    BODY="eShield $TAG release."
fi

echo "==> 创建 GitHub Release $TAG"
RESPONSE=$(curl -s -X POST \
    -H "Authorization: token $GH_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    "https://api.github.com/repos/$REPO/releases" \
    -d "{\"tag_name\":\"$TAG\",\"name\":\"eShield $TAG\",\"body\":\"$BODY\",\"draft\":false,\"prerelease\":false}")

UPLOAD_URL=$(echo "$RESPONSE" | grep -o '"upload_url": *"[^"]*' | sed 's/"upload_url": *"//;s/{?name,label}$//' | head -1)
if [ -z "$UPLOAD_URL" ]; then
    echo "创建 release 失败，接口返回："
    echo "$RESPONSE"
    exit 1
fi

echo "==> 上传产物"
if [ -n "$ASSET_DIR" ] && [ -d "$ASSET_DIR" ]; then
    for F in "$ASSET_DIR"/*; do
        [ -f "$F" ] || continue
        ASSETS+=("$F")
    done
else
    ASSETS=("${DEFAULT_ASSETS[@]}")
fi

if [ ${#ASSETS[@]} -eq 0 ]; then
    echo "错误：未找到任何产物"
    exit 1
fi

for F in "${ASSETS[@]}"; do
    if [ ! -f "$F" ]; then
        echo "警告：产物不存在，跳过 $F"
        continue
    fi
    NAME=$(basename "$F")
    echo "  上传 $NAME ..."
    curl -s -X POST \
        -H "Authorization: token $GH_TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$F" \
        "$UPLOAD_URL?name=$NAME" >/dev/null
    echo "  ✓ $NAME"
done

echo ""
echo "==> 发布完成：https://github.com/$REPO/releases/tag/$TAG"
