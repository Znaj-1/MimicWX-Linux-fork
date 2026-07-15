#!/bin/bash
# 自动提取派生密钥并写入 wechat_keys.json
# 等 90 秒让微信启动 + 扫码登录
sleep 90

echo "[auto_keys] 开始提取派生密钥..."

# 找微信数据目录
DB_DIR=$(find /home/wechat -path "*/db_storage" -type d 2>/dev/null | head -1)
if [ -z "$DB_DIR" ]; then
    echo "[auto_keys] 未找到 db_storage, 退出"
    exit 0
fi

echo "[auto_keys] db_dir=$DB_DIR"

# 写临时 config
cat > /tmp/wd_config.json <<CONF
{
  "db_dir": "$DB_DIR",
  "keys_file": "all_keys.json",
  "decrypted_dir": "decrypted",
  "decoded_image_dir": "decoded_images",
  "wechat_process": "wechat",
  "image_aes_key": "",
  "image_xor_key": 0
}
CONF

# 提取密钥
cd /usr/local/bin/wechat-decrypt
python3 -c "
import json, sys, os
sys.path.insert(0, '.')

# 覆盖 config
import importlib
import wd_config as config
config._config_path = '/tmp/wd_config.json'
config._config = json.load(open('/tmp/wd_config.json'))

# 运行提取
exec(open('find_all_keys_linux.py').read())
" 2>&1 | tail -5

# 转成 wechat_keys.json
python3 -c "
import json, os
keys_file = '/usr/local/bin/wechat-decrypt/all_keys.json'
if not os.path.exists(keys_file):
    keys_file = 'all_keys.json'
if not os.path.exists(keys_file):
    print('[auto_keys] all_keys.json 不存在, 提取可能失败')
    exit(1)
keys = json.load(open(keys_file))
result = {}
for db_path, info in keys.items():
    if isinstance(info, dict):
        result[db_path] = info.get('enc_key', info.get('key', ''))
    else:
        result[db_path] = info
os.makedirs('/home/wechat/.xwechat', exist_ok=True)
json.dump(result, open('/home/wechat/.xwechat/wechat_keys.json', 'w'), indent=2)
json.dump(result, open('/tmp/wechat_keys.json', 'w'), indent=2)
print(f'[auto_keys] 写入 {len(result)} 个密钥到 wechat_keys.json')
"
