#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy-route.py — 本地白名单路由代理
====================================
默认直连：白名单内的域名 / IP 走远程代理，其余流量本地直连（低延迟）。
支持 HTTP 与 HTTPS（CONNECT 隧道）。所有 CLI 工具（curl/wget/git/python/npm）
只需把 http_proxy/https_proxy 指向本代理，即可获得统一的"默认直连 + 白名单走代理"。

用法:
  proxy-route.py <config.json>

config.json 格式（由 proxy.sh on 时生成）:
{
  "listen_port": 18080,
  "proxy_host": "10.100.96.156",
  "proxy_port": 8798,
  "whitelist": ["github.com", "10.0.0.0/24"]
}
"""
import json
import logging
import socket
import sys
import threading

LOG = logging.getLogger("proxy-route")

# ================= 白名单匹配 =================
class Router:
    def __init__(self, conf):
        self.proxy_host = conf["proxy_host"]
        self.proxy_port = int(conf["proxy_port"])
        self.whitelist = [str(x).strip() for x in conf.get("whitelist", [])]
        self.shutdown_flag = False

    def is_whitelisted(self, host):
        h = host.strip()
        if h.startswith("["):                      # IPv6 [::1]:443
            h = h.split("]", 1)[0] + "]"
        if h.count(":") == 1 and not h.startswith("["):   # host:port
            h = h.rsplit(":", 1)[0]
        h = h.strip("[]")
        if not h:
            return False
        for e in self.whitelist:
            if not e:
                continue
            if "/" in e:                           # CIDR: 10.0.0.0/24
                if self._in_cidr(h, e):
                    return True
            elif e.startswith("."):                # .example.com 仅子域
                if h.endswith(e):
                    return True
            else:                                  # example.com 精确+子域
                if h == e or h.endswith("." + e):
                    return True
        return False

    @staticmethod
    def _in_cidr(host, cidr):
        try:
            import ipaddress
            return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

# ================= 连接处理 =================
def read_head(client):
    """读取请求行+头部，返回 (head_bytes, head_str, 头部之后的剩余字节)"""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 1024 * 1024:
            break
    head, _, rest = data.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", head.decode("latin-1", "replace"), rest


def parse_head(head_str):
    lines = head_str.split("\r\n")
    request_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return request_line, headers


def relay_loop(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def upstream_connect(host, port, timeout=15):
    # 仅 IPv4：先解析出 IPv4 地址再连接。create_connection 直接传域名时
    # 会按系统顺序解析（IPv6 优先），本机公网 IPv6 无连通性，SYN 会卡满
    # timeout 才回退，导致每个直连请求都挂起
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    last_err = None
    for info in infos:
        sock = socket.socket(*info[:3])
        sock.settimeout(timeout)
        try:
            sock.connect(info[4])
            return sock
        except OSError as e:
            last_err = e
            sock.close()
    raise last_err if last_err else OSError("no IPv4 address: %s" % host)


def handle_connect(client, hostport, rest, router):
    """HTTPS 隧道：白名单→远程代理 CONNECT；否则→目标直连"""
    if ":" not in hostport:
        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    host, _, port_s = hostport.rpartition(":")
    port = int(port_s) if port_s.isdigit() else 443
    try:
        if router.is_whitelisted(host):
            upstream = upstream_connect(router.proxy_host, router.proxy_port)
            req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)).encode()
            upstream.sendall(req)
            rhead, rstr, _ = read_head(upstream)
            if " 200 " not in rstr.split("\r\n", 1)[0]:
                client.sendall(rhead if rhead else b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                upstream.close()
                return
        else:
            upstream = upstream_connect(host, port)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except OSError as e:
        LOG.warning("CONNECT %s 失败: %s", hostport, e)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass
        return
    if rest:
        try:
            upstream.sendall(rest)
        except OSError:
            pass
    _relay_pair(client, upstream)


def handle_http(client, request_line, headers, rest, router, head_bytes):
    """HTTP 请求：白名单→转发远程代理；否则→改写为 origin-form 直连"""
    parts = request_line.split()
    if len(parts) < 3:
        return
    method, target = parts[0], parts[1]
    host = headers.get("host", "")
    hostname = host.rsplit(":", 1)[0].strip("[]") if host else ""
    if not hostname and (target.startswith("http://") or target.startswith("https://")):
        from urllib.parse import urlparse
        hostname = urlparse(target).netloc.rsplit(":", 1)[0]
    port = 80
    if ":" in host and not host.startswith("["):
        _, _, ps = host.rpartition(":")
        port = int(ps) if ps.isdigit() else 80

    try:
        if router.is_whitelisted(hostname):
            upstream = upstream_connect(router.proxy_host, router.proxy_port)
            out_head = head_bytes                     # 代理可接受原样
        else:
            upstream = upstream_connect(hostname, port)
            # 直连需 origin-form 请求行
            path = target
            if target.startswith("http://") or target.startswith("https://"):
                from urllib.parse import urlparse
                p = urlparse(target)
                path = p.path or "/"
                if p.query:
                    path += "?" + p.query
            out_head = head_bytes.replace(target.encode(), path.encode(), 1)
    except OSError as e:
        LOG.warning("HTTP %s %s 失败: %s", method, hostname, e)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass
        return

    try:
        upstream.sendall(out_head)
        if rest:
            upstream.sendall(rest)
    except OSError:
        upstream.close()
        return
    _relay_pair(client, upstream)


def _relay_pair(a, b):
    t1 = threading.Thread(target=relay_loop, args=(a, b), daemon=True)
    t2 = threading.Thread(target=relay_loop, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


class ClientHandler:
    def __init__(self, client, router):
        self.client = client
        self.router = router

    def run(self):
        try:
            head_bytes, head_str, rest = read_head(self.client)
            if not head_str:
                return
            request_line, headers = parse_head(head_str)
            parts = request_line.split()
            method = parts[0].upper() if parts else ""
            if method == "CONNECT":
                hostport = parts[1] if len(parts) >= 2 else ""
                handle_connect(self.client, hostport, rest, self.router)
            elif method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                handle_http(self.client, request_line, headers, rest, self.router, head_bytes)
            else:
                self.client.sendall(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
        except Exception as e:                      # 不因单个连接崩溃
            LOG.debug("处理连接异常: %s", e)
        finally:
            try:
                self.client.close()
            except OSError:
                pass


def serve(router, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    srv.settimeout(0.5)
    LOG.info("本地白名单路由代理已启动 127.0.0.1:%d → 远程代理 %s:%d（默认直连）",
             port, router.proxy_host, router.proxy_port)
    while not router.shutdown_flag:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=ClientHandler(conn, router).run, daemon=True).start()
    srv.close()
    LOG.info("代理已退出")


def main():
    if len(sys.argv) < 2:
        print("用法: proxy-route.py <config.json>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1]) as f:
        conf = json.load(f)
    port = int(conf.get("listen_port", 18080))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    router = Router(conf)
    try:
        serve(router, port)
    except KeyboardInterrupt:
        router.shutdown_flag = True


if __name__ == "__main__":
    main()
