#!/bin/bash
# 启动 friends_api.py（好友/群聊分类接口）
# 用法: bash api/start_friends.sh
# 放在 MimicWX-Linux/api/ 目录下，跨设备通用
# 配置: cp api/.env.example api/.env 然后填入 MIMICWX_TOKEN
DIR="$(cd "$(dirname "$0")" && pwd)"

# 加载 .env 环境变量（每台机器各自配置，不提交到 git）
if [ -f "$DIR/.env" ]; then
    set -a
    source "$DIR/.env"
    set +a
fi

pkill -f friends_api.py 2>/dev/null
sleep 1
setsid bash -c "cd \"$DIR\" && python3 friends_api.py </dev/null >/tmp/friends_api.log 2>&1" &
sleep 1
echo "friends_api started, pid=$(pgrep -f friends_api.py | head -1), log=/tmp/friends_api.log"
