# whitelane

> 默认直连 + 白名单走代理的智能分流方案：远程代理只服务白名单，其余流量本地直连。

远程代理服务器通常延迟较高（跨国链路），如果所有流量都绕它一圈会很慢。
`whitelane` 的思路是：**只有白名单里的域名/IP 才走远程代理，其余默认直连**。

- 访问 B 站 → 本地直连，低延迟
- 访问 GitHub / Google / Twitter/X → 走远程代理，能通且快
- 浏览器与命令行（curl / wget / git / npm / pip）统一生效

## 特性

- 🚦 **白名单分流**：`whitelist.yaml` 一行一个域名/IP/CIDR，白名单走代理、其余直连
- 🔔 **敲门认证（SPA）**：客户端带 token 敲一下认证端口，服务端用 iptables `recent` 授权该 IP，静默 8 小时自动过期，无需账号密码
- 🖥️ **命令行统一生效**：`route` 模式本地起路由代理，curl / wget / git / npm / pip 全都按同一套白名单分流
- 🌐 **浏览器统一生效**：GNOME 系统代理指向本地路由代理，GUI 应用同一套规则
- 🧩 **服务端 / 客户端分离**：一份仓库收纳两端，服务端基于 [gost](https://github.com/go-gost/gost)

## 目录结构

```
whitelane/
├── client/                  # 客户端（本机运行）
│   ├── proxy.sh             # 主脚本：on/off/status，配置系统代理 + 环境变量
│   ├── proxy.conf           # 代理服务器信息、命令行模式
│   ├── whitelist.yaml       # 白名单（YAML 列表）
│   └── proxy-route.py       # 本地路由代理（route 模式的分流引擎）
└── server/                  # 服务端（远程代理服务器）
    ├── start-gost.sh        # gost + 认证守护进程启动器（systemd 调用）
    ├── proxy-auth.py        # 敲门认证服务（iptables recent 动态授权）
    └── gost.service         # systemd 单元
```

## 快速开始

### 客户端

```bash
# 1. 编辑 proxy.conf 填入代理服务器信息，编辑 whitelist.yaml 填入白名单
# 2. 开启（会先敲门认证，再配置系统代理并输出命令行环境变量）
whitelane on

# 3. 在 ~/.bashrc 里放一个函数，让子 shell 也能拿到代理变量：
whitelane() {
    eval "$(/path/to/whitelane/client/proxy.sh "$@")"
}

# 4. 关闭
whitelane off
```

`whitelane` 的命令行有三种模式（`proxy.conf` 里 `CLI_MODE` 指定）：

| 模式 | 说明 |
|------|------|
| `route`（推荐） | 本地路由代理分流：白名单→远程，其余→直连，所有 CLI 工具统一生效 |
| `proxy` | 导出环境变量指向远程代理，`no_proxy` 排除内网/本地 |
| `direct` | 不导出代理变量，默认直连；单条命令用 `proxyrun` 包装走代理 |

### 服务端

```bash
# 1. 安装 gost 到 server/ 目录
# 2. 编辑 server/proxy-auth.py 顶部的 SECRET_TOKEN（与客户端一致）
# 3. 安装 systemd 单元并启动：
sudo cp server/gost.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gost
```

## 配置说明

### whitelist.yaml（白名单）

```yaml
# example.com      精确匹配，并包含其所有子域（www/api/drive...）
# .example.com     只匹配子域，不匹配根域
# 10.0.0.0/24     IP 网段（0.0.0.0/0 表示全部 IP）
- github.com
- google.com
- x.com
```

### 敲门认证流程

```
客户端                         服务端 (10.100.96.156)
  │  GET /auth?token=xxx ───────►│  proxy-auth.py (:8799)
  │  ← 200 授权成功              │  写入 /proc/net/xt_recent/GOST_AUTH
  │                              │  iptables recent --update --seconds 28800 → ACCEPT
  │  随后通过 :8798 访问代理 ────►│  gost（防火墙只放行 recent 列表内的 IP）
```

## 许可证

MIT
