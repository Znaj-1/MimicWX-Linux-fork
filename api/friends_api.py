#!/usr/bin/env python3
"""好友/群聊分类接口 — 代理 MimicWX /contacts + /sessions，只返回可发消息的对象

环境变量（通过 api/.env 或系统环境变量配置）:
  MIMICWX_TOKEN   MimicWX API 认证 Token（必填，从 config.toml 的 token 字段获取）
  MIMICWX_URL     MimicWX API 地址（可选，默认 http://localhost:8899）
  FRIENDS_API_PORT 监听端口（可选，默认 9000）
"""
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.request

MIMICWX_URL = os.environ.get("MIMICWX_URL", "http://localhost:8899")
TOKEN = os.environ.get("MIMICWX_TOKEN", "")
PORT = int(os.environ.get("FRIENDS_API_PORT", "9000"))

if not TOKEN:
    print("ERROR: 未设置 MIMICWX_TOKEN")
    print("请在 api/.env 中配置，或: export MIMICWX_TOKEN='your_token'")
    raise SystemExit(1)

SYSTEM_ACCOUNTS = {
    "weixin", "medianote", "notifymessage", "fmessage", "filehelper",
    "wxid_6mv6063zkf1p22",
}


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode())

    def _get(self, path):
        req = urllib.request.Request(
            f"{MIMICWX_URL}{path}",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())

    def do_GET(self):
        if not self.path.startswith("/friends"):
            self._json(404, {"error": "not found"})
            return

        try:
            contacts = self._get("/contacts").get("contacts", [])
            sessions = self._get("/sessions")

            # 有会话记录的 username 集合
            session_users = {s.get("username", "") for s in sessions}

            friends = []
            groups = []
            for c in contacts:
                uid = c.get("username", "")
                name = c.get("display_name", "") or c.get("nick_name", "")
                remark = c.get("remark", "")
                alias = c.get("alias", "")

                if "@chatroom" in uid:
                    groups.append({"name": name, "username": uid})
                elif uid in SYSTEM_ACCOUNTS or uid.startswith("gh_"):
                    continue
                elif uid in session_users:
                    # 只返回有过会话记录的个人（真正能发消息的）
                    friends.append({
                        "name": name,
                        "username": uid,
                        "remark": remark,
                        "alias": alias,
                    })

            self._json(200, {"friends": friends, "groups": groups})
        except Exception as e:
            self._json(500, {"error": str(e)})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Friends API: http://0.0.0.0:{PORT}/friends")
    server.serve_forever()
