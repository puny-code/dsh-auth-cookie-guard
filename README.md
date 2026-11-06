# 启动 Cookie 守护（dsh-auth-cookie-guard）

修复 DSH 桌面版「固定 profile 启动约 72 次后永久报 `desktop welcome: Web authentication failed`」的问题。

> 本仓库是 [jitianjiyan/dsh-auth-cookie-guard](https://github.com/jitianjiyan/dsh-auth-cookie-guard) 的 fork（1.0.7）。相对上游 1.0.6 只做了一处改动：**监听器晚绑定不再等于不守护**。其余设计与验证结论沿用上游。

## 症状

- 固定 profile（固定 `userData`）连续启动约 72 次之后，桌面端再也进不去，日志里是 `desktop welcome: Web authentication failed`（`app.asar/lib/main.js:8886` 的 `connectDesktopWelcome`）。
- 重启、撤销授权、重装都无效，只有换掉整个 profile（也就是换掉 Chromium 的 cookie 库）才能恢复。

## 根因

1. Host 每次启动都绑定随机端口；浏览器会话 cookie 按授权方命名：
   `dsh-auth-<base64url(sha256(host:port))>`（`dsh-client-connection/lib/index.js:277`、`:335-337`）。
2. 浏览器按**域名**存 cookie，端口不进键。于是每启动一次，`127.0.0.1` 上就多一条约 173 字符、`Max-Age` 30 天的持久 cookie，且没有任何代码删除它们。
3. Host 建监听器时没有覆盖头部预算——`createServer(listener)`（`dsh-host-webserver/lib/index.js:412`）——因此沿用 Node 默认的 `maxHeaderSize = 16384` 字节。
4. 第 71 条累积后 `Cookie` 头约 16184 字节，本轮再下发 1 条即约 16411 字节，超过 16384，Node 直接返回 `431`；客户端把它当成认证失败。此后每次启动都超过上限，而 431 的请求根本到不了应用层，也就没有任何机会清理——故障是纯累积型且不可自愈的。

## 1.0.7 修了什么：监听器晚绑定不再等于不守护

上游 1.0.6 在 `apply()` 里这样开头：拿不到 `ctx.webServer.server` 就打一条 warn 然后 `return`。这条路径不是理论问题——cordis 的 `Service` 构造时就完成 `provide`（`cordis/lib/index.js:1770-1784` 的 `ctx.reflect.provide`），而真正 `createServer` 是在之后的 `[Service.init]`（同文件 `:1069-1071`）里做的。所以按组合层的加载顺序，插件完全可能在 `webServer.server` 还是 `undefined` 的时刻 apply，结果是**装着、日志也正常，但一个字节都没守护**：预算没抬、cookie 不退休，故障照旧在第 72 次启动出现，而且看起来像是「插件无效」。

1.0.7 把「晚绑定」当成必须处理的状态：

- 能立刻绑就立刻绑；绑不到就每 100 ms 重试一次，最多 10 s（`RECHECK_MS` / `RECHECK_LIMIT`），期间日志是 `waiting for webServer to bind…`。
- 10 s 内始终没有监听器，则用 `logger.error` 明确报出「预算没抬、cookie 不会退休」，而不是安静地什么都不做——宁可吵，也不要假装守护成功。
- `bind()` 幂等且可重入（组合重载会重新 apply），只升不降：监听器自己已经带了更大的预算就保持原值。
- dispose 时移除监听、还原预算，且只在「当前值仍是本插件写入的值」时才还原，不会覆盖别人后来的改动。

对应 4 个新回归用例：晚绑定的监听器在 apply 之后被抬起并在首个请求上退休 cookie、dispose 后预算还原、监听器原有更大预算被保留且 dispose 后仍保留、换一个监听器（组合重载）重新接管。

## 插件做了什么

两层防护，缺一不可：

| 层 | 行为 | 默认值 |
| --- | --- | --- |
| 头部预算 | 在 `webServer` 服务就绪后把 `server.maxHeaderSize` 提升到 64 KiB | `maxHeaderBytes: 65536` |
| 退休旧 cookie | 每个请求只读取 `Cookie` 头里的名字（必须是 `dsh-auth-<43 位 base64url>`）；按浏览器发送顺序（旧→新）保留最后 `keep` 条 + 当前端口那一条，其余用 `Max-Age=0; Path=/` 从浏览器 jar 删除（每个响应最多 96 条，约 12 KiB） | `keep: 4` |

几点设计取舍：

- **为什么两层都要**：只提升预算，约 350 次启动后依旧会撞墙（只是把 72 次变成 350 次）；只清理而不提升预算，则清理逻辑永远跑不到——431 在 Node 的 HTTP 解析层就被拒了，请求不会进入监听器。
- **为什么只读名字、不解码 cookie 值**：cookie 值是 DSH 的签名会话载荷（`authority`/`issuedAt`/`expiresAt`）。这些 cookie 都是 `Path=/`，浏览器按创建时间从旧到新发送（RFC 6265 §5.4），所以位置本身就能排出新旧；名字足够定位，值既不参与认证判断，也不再被解析、记录或使用。
- **为什么保留当前端口那条**：即使 `keep` 配得很小、或系统时钟回拨，也不会把正在使用的那条 cookie 删掉。
- **为什么用 `Max-Age=0` 而不是改名或重写**：cookie 名与端口/协议绑定（`requestAudience`），改名会让认证查不到；重签名需要密钥。删除是唯一不改变语义的收敛方式。
- **对异常格式零影响**：只匹配 `dsh-auth-` + 43 位 base64url 的精确形状；cookie 值里带什么（包括伪造的 `issuedAt`）都不影响保留/删除结果。若未来 cookie 名字格式变化，退化结果是「预算提升、不再清理」，而不是破坏会话。
- **不会越界**：只处理 `webServer` 自己的局域网/本机监听器；其它 profile 的 host 有独立 cookie 库，互不影响。
- **为什么单响应最多删 96 条**：删除行长度由固定名字形状决定（约 125 字节/条），96 条约 12 KiB，留在 Node HTTP 客户端默认 16 KiB 响应头预算之内——实测 128 条（约 16 KiB）会让 `fetch` 解码握手直接失败。更大的 jar 不会丢清理，只是在后续请求里分批删完，绝不会用一条超大的响应头去赌客户端容忍度。
- **64 KiB 为什么够**：Chromium 对单域名有条数上限（180 条），每条 minted cookie 约 173 字符，理论上限约 33 KB，已经落在 64 KiB 之内。即使一个已经被锁死的 jar 条数拉满，也能在第一次握手时被放行，并当场收敛。

## 安全边界

- **只看请求自己的 cookie**：插件在 Host 进程内只能看到发往本监听的请求所携带的 Cookie，也就是请求者自己浏览器的那一份；不跨用户、不读取磁盘上的其他 cookie 库。
- **只读名字与顺序**：从 1.0.4 起不解码 cookie 值、不记录任何 cookie 名字或值；整个包只 import `node:crypto`，没有网络、文件、子进程调用。回归测试里有一例专门守着「名字和值不进日志」。
- **不参与认证**：它从不改写、重签或保留认证凭据，也不做登录判断；删除指令只是把请求者自己 jar 里本次实例不再用的启动 cookie 清掉，认证仍由 DSH 自己的签名校验负责。
- **头部预算的副作用**：默认把监听器的 `maxHeaderSize` 提到 64 KiB。默认回环监听下这只影响本机；如果把 DSH 绑到回环之外，远端请求可以多占每连接头部内存——对外暴露时应加反向代理/访问控制，或把 `maxHeaderBytes` 调低。
- **同 host 多实例**：浏览器 cookie 按 host 共享，插件会退休「最新 `keep` 条 + 当前端口」之外的启动 cookie；同一份 profile 同时跑多个实例时，较旧实例的登录可能被清理，需要重新走一次欢迎页握手。当前实例自己的 cookie 始终保留。

## 配置

在 profile 的 patch 层给这一行加 `config` 即可（`maxHeaderBytes` 会被夹到 16 KiB–1 MiB，`keep` 到 1–64）：

```yaml
- id: auth-cookie-guard
  name: dsh-auth-cookie-guard
  config:
    maxHeaderBytes: 131072
    keep: 4
```

一般不需要改。若某台机器上 cookie 已经多到超过 64 KiB（约 350 次启动），把 `maxHeaderBytes` 临时调到 `262144`，启动一次让清理跑完，再调回默认值即可。

## 安装与卸载

- 安装（本 fork）：插件页填 git 地址 `git+https://github.com/puny-code/dsh-auth-cookie-guard.git`，或本地源码目录（工具会以 `link:` 方式引入）。工具会把它写进 profile 的 `package.json`（`dsh.profile.bundles` 与依赖）；本 bundle 自带的 `cordis.patch.yml` 作为独立层插入那一行，profile 自己的 `cordis.patch.yml` 不需要任何改动。不要手改 profile 文件。
- 已锁死的 profile 也能救回来：装上之后**下一次启动**的握手就会被放行（预算先抬），并在同一个响应里把旧 cookie 批量删掉；不需要换 profile、不需要撤销授权。若 jar 大到超过 64 KiB，按上面「配置」一节临时抬到 `262144` 跑一次即可。
- 生效方式：安装时宿主会重载组合，插件当场 apply，无需重启桌面端；之后每次启动同样自动生效。
- 卸载：在插件管理中移除该 bundle，重启桌面端；卸载后会恢复监听器的原始头部预算（插件在 dispose 时还原）。
- 本插件只有 Host 端，没有浏览器端资源，也没有 service / tool / event。
- npm 上只有上游的 1.0.1–1.0.6，本 fork 的 1.0.7 不发布到 npm，请按上面的 git / 本地路径安装。

## 验证

用一个真实的 `node:http` 服务器模拟 71 条旧 cookie + 本轮 1 条（构造方式与报告一致）：

```
cookie header bytes: 16414
BEFORE: {"status":431}                       # 安装前：与线上故障同因
[info] auth-cookie-guard: listener header budget 65536 bytes, keeping 4 launch cookie(s)
[info] auth-cookie-guard: retired 68 launch cookie(s), kept 4
AFTER: status 200 deletions 68               # 安装后：握手通过，并当场清掉 68 条
kept names: 4 (current kept)                 # 最新 4 条保留，当前端口那一条保留
maxHeaderSize now: 65536
AFTER PRUNE: 200 deletions 0                 # 第二次请求不再产生删除头（幂等）
maxHeaderSize restored: undefined            # dispose 后还原
```

线上验证（对本机已安装、正在运行的宿主直接探测，插件安装后即时生效；环境为 DSH 0.2.1-rc.5 桌面版）：

```
big header 20KB:  {"status":401}            # 提升预算前这里是 431
71 cookies:       401 deletions: 67         # 当场退休 67 条，保留最新 4 条
```

第一行说明请求已经进入应用层（401 是未认证的正常响应，而不是 Node 在解析层回的 431），即 `maxHeaderSize` 已抬到 64 KiB；第二行说明裁剪逻辑在真实请求上生效（这 71 条里有一条就是该端口的当前 cookie，所以删 67 条、留 4 条）。宿主日志同时会打印
`auth-cookie-guard: listener header budget 65536 bytes, keeping 4 launch cookie(s)` 与
`auth-cookie-guard: retired N launch cookie(s), kept 4`，此后无论重启多少次都不再累积。

晚绑定路径另外单独验证过：给一个 `apply` 时还没有 `server` 的 ctx，100 ms 内出现的监听器会被抬起预算，并在它的首个请求上退休 cookie（测试 15）；10 s 内不出现则报 error。

回归测试 `npm test`（18 例）覆盖：303 对象写头（真实握手路径）、隐式 200、三参数写头、平铺数组写头、`appendHeader` 多值、无清理时不包装 `writeHead`、64 KiB 预算下 200 条 cookie（约 19 KiB）仍能握手、400 条 jar 分 5 轮各 ≤96 条收敛且客户端不报错、按顺序而非 cookie 值排序、名字和值不进日志，以及 1.0.7 新增的 4 例晚绑定/还原/只升不降/重载接管——旧实现会在 303 上丢掉全部删除指令，128 条的上限也会让 `fetch` 解码失败。

## 环境

Windows 11、DSH 0.2.1-rc.3 与 0.2.1-rc.5 桌面版（1.0.6/1.0.7 在 rc.5 上实测生效）、Electron 44.7.0、Node 24.21.0（本机复现用 Node 24.18.0、验证脚本用 Node 22.22.3）。`server.maxHeaderSize` 在运行时赋值即对后续连接生效，这一点已在 Node 24 与 Node 22 上实测（431 → 200，70000 字节 → 431）。
