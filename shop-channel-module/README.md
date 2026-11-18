# 商城安全与地区规则模块（PHP，本地 API 原型）

这是可运行、已测试的独立 API 模块，不是已经接入商城的完整后台 UI。它不识别广告审核、机器人身份或 UA，不提供公开落地页 IP 分流、替换页面或任意外部跳转。明确的渠道链接可 302 到同站商品／集合路径，对所有请求者一致。根页面对所有访客返回完全一致的 JSON。未部署、未连接任何真实会员或支付系统。

## 功能

- **管理后台地址白名单**：IPv4、IPv6、CIDR，单条或最多 500 条批量导入；规范化地址；最长 366 天到期；删除；操作日志。只保护 `/admin/*`。白名单为空时拒绝远程管理访问；回环地址保留恢复入口，但仍强制验证管理令牌。
- **指定业务操作防刷**：仅 `login`、`register`、`coupon`，`observe`（默认只记录）或 `limit`；原子计数，超限 429 / Retry-After。业务接口地址拒绝规则优先执行，命中返回 403，即使计数策略为 observe 也拒绝；observe 仅控制频率限制。固定窗口可能在窗口边界容许两倍短时突发，这是明确的算法限制。没有“机器人识别准确率”承诺。
- **商品配送规则**：按商品 SKU 和收货国家判断可售；未知 SKU 默认不允许；空国家列表等于暂停该 SKU 配送。与 IP、渠道、审核身份无关。
- **变更日志**：记录地址库、限制策略、商品规则变更，最近 100 条查询。数据库里的日志不是防篡改审计系统。

## 本地启动

需要 PHP 8.2+，PDO SQLite 扩展，无 Composer/Redis/MySQL 依赖。已在 PHP 8.5.4 验证。

```sh
cd shop-channel-module
umask 077
export SHOP_ADMIN_TOKEN="$(php -r 'echo bin2hex(random_bytes(32));')"
export SHOP_INTEGRATION_TOKEN="$(php -r 'echo bin2hex(random_bytes(32));')"
# 两个令牌必须独立，不能发给浏览器或放进前端代码。
php -S 127.0.0.1:8088 -t public public/index.php
```

另一个终端需要相同环境变量才能调用接口；不要把真实令牌发给助手或写到仓库。`SHOP_DB` 可指定数据库绝对路径，默认 `var/shop.sqlite`。存储目录必须位于 Web 根目录之外，生产系统权限设置由部署负责人执行。

测试：

```sh
php tests/run.php
php tests/defense.php
python3 tests/cgi_smoke.py  # 需要 php-cgi，无需监听端口
python3 tests/http_smoke.py # 可选，需要本机回环端口权限
php tests/defense.php
php tests/channels.php
find src public tests -name '*.php' -exec php -l {} \;
```

## API 合同

所有输入为 JSON，变更上限 64 KiB，无 Cookie 会话、无 CORS 放行。每次请求携带相应 Bearer 令牌。错误采用 400 / 401 / 403 / 404 / 413 / 415 / 429 / 503；HTTP 200 的配送检查仍必须读取 `allowed`。

| 方法 / 路径 | 凭据 | 用途 |
|---|---|---|
| GET `/` | 无 | 固定公开状态，不使用 IP、UA 或地域分流 |
| GET `/admin/networks` | 管理令牌 + 网络白名单 | 列出后台准入地址 |
| POST `/admin/networks` | 同上 | `{"entries":[{"cidr":"192.0.2.0/24","expires_at":整数Unix秒,"note":"临时办公网络"}]}` |
| DELETE `/admin/networks/{id}` | 同上 | 删除一条准入记录 |
| GET `/admin/rates` | 同上 | 列出三个固定操作的策略 |
| PUT `/admin/rates` | 同上 | `{"scope":"login","mode":"limit","max_hits":20,"window_seconds":60}` |
| GET `/admin/products` | 同上 | 列出规则，`countries` 为 JSON 编码字符串 |
| PUT `/admin/products` | 同上 | `{"product":"SKU001","countries":["BR","AM"]}` |
| GET `/admin/audit` | 同上 | 最近 100 条变更记录 |
| POST `/internal/rate/consume` | 集成令牌 | `{"scope":"login","subject":"64位小写十六进制HMAC","client_ip":"服务器确认的客户端地址"}` |
| POST `/internal/shipping/check` | 集成令牌 | `{"product":"SKU001","shipping_country":"BR"}` |

`expires_at` 是 UTC Unix 秒，不是日期字符串。后台白名单的 CIDR /0 可以表示整个地址族，仅应在本地测试使用；管理令牌始终必需。业务接口拒绝库禁止 /0（包括映射后的 /0），避免误封整个地址族。客户端不得自行决定限流的 `subject`；由受信商城服务器用独立密钥对账户标识或正确识别的客户端地址做 HMAC-SHA256。不要传原始手机号、邮箱或密码。登录与注册可采用单独客户端/账户键；领券还必须有商城自身的用户鉴权及业务唯一性约束，本模块不代替这些检查。策略修改会清空对应操作计数，从下一次请求重新计数。

示例：

```sh
curl -H "Authorization: Bearer $SHOP_ADMIN_TOKEN" \
 -H 'Content-Type: application/json' -X PUT \
 -d '{"product":"SKU001","countries":["BR"]}' \
 http://127.0.0.1:8088/admin/products

curl -H "Authorization: Bearer $SHOP_INTEGRATION_TOKEN" \
 -H 'Content-Type: application/json' \
 -d '{"product":"SKU001","shipping_country":"BR"}' \
 http://127.0.0.1:8088/internal/shipping/check
```

## 接入真实商城前必须完成

1. 仅通过本机/受保护内部网络调用集成端点。用 HTTPS 或本机 Unix/回环通道；禁止把管理和集成令牌放前端。增加真正的管理账号、权限、登录防刷和密钥轮换。本原型没有管理网页和用户身份系统。
2. 本模块**忽略所有转发头**，只使用 REMOTE_ADDR 作后台网络判断。如果经本地反向代理访问，REMOTE_ADDR 可能都是回环，从而网络门禁只能看到代理。不要因此直接公开 `/admin/*`；部署前必须在受信网关完成真实来源校验，或让管理入口仅走安全内部网络。不得盲目信任 X-Forwarded-For / CF-Connecting-IP。
3. 配送检查应放在服务器创建订单、确认收货地址和支付前；地址变更需重检。从实际地址提取标准国家代码；本模块只验证大写双字母格式，业务系统须验证真实 ISO 国家值和地址。混合购物车逐商品校验，不只检查一个 SKU。不依赖浏览器自己提交“允许”结果。
4. 限流服务不可用时，领券等高风险操作应拒绝执行或返回明确的稍后重试，不默默放行。现有账户、支付、归因和 API 语义保持不变。
5. SQLite 只适合该单机原型/低并发部署。规模化时将原子计数迁移到 Redis，配置持久化迁移到正式数据库并验证并发事务；没有负载或高可用验收。
6. 最小化日志、配置保留周期、备份与权限。计数器过期记录在下一次计数时删除；审计日志尚无自动归档。
7. 管理与集成响应设置 no-store；不要缓存登录、订单或个人响应。公开页面不挂载地址库/机器人识别逻辑。

所有示例地址均为文档保留地址，未导入任何平台、审核或机器人地址库。


## 业务接口 IPv4 / IPv6 拒绝库（新增，非公开访客分流）

这套库只在通过集成令牌认证的 `/internal/rate/consume` 中生效，固定为登录、注册、领券三个业务操作。拒绝时返回 403 JSON；超频返回 429 JSON；无 302、无跳转目标、无任意 URL/路径规则、无机器人类别或 UA 条件。公开首页不读取此库。不能把此接口接成所有公开页面的全局访问门禁。

- `GET /admin/operation-denies`：列出记录，含到期记录。
- `POST /admin/operation-denies`：1–500 条批量导入，按操作与规范化 CIDR 去重更新；整体校验失败不导入任何记录。
- `PUT /admin/operation-denies/{id}`：完整更新一条记录；不存在返回 404，冲突返回 400。
- `DELETE /admin/operation-denies/{id}`：移除一条；不存在返回 404。
- 各变更均记入 `/admin/audit`。

示例（文档专用 IP，不用于生产）：

```sh
EXPIRY=$(php -r 'echo time()+3600;')
curl -H "Authorization: Bearer $SHOP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
 -d "{\"entries\":[{\"scope\":\"login\",\"cidr\":\"192.0.2.0/24\",\"expires_at\":$EXPIRY,\"note\":\"本地测试\"}]}" \
 http://127.0.0.1:8088/admin/operation-denies

curl -H "Authorization: Bearer $SHOP_ADMIN_TOKEN" \
 http://127.0.0.1:8088/admin/operation-denies

# 按上一条列表返回的真实 id 替换 1。
curl -X PUT -H "Authorization: Bearer $SHOP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
 -d "{\"scope\":\"register\",\"cidr\":\"2001:db8::/32\",\"expires_at\":$EXPIRY,\"note\":\"更新测试\"}" \
 http://127.0.0.1:8088/admin/operation-denies/1

curl -X DELETE -H "Authorization: Bearer $SHOP_ADMIN_TOKEN" \
 http://127.0.0.1:8088/admin/operation-denies/1
```

### SECURITY 与集成边界

- 管理令牌和集成令牌必须**同时配置、至少 32 字节且互不相同**；不满足时受保护端点返回 503。
- `client_ip` 来自拥有登录/注册/领券业务的受信服务器观测值，不是客户端表单，也不是未经验证的请求头。商城应用若在代理后，先限定受信代理链并可靠恢复原始来源。不要把调用本模块的服务器 IP 当访客 IP。
- 缺失或非法 `client_ip` 返回 400，不默默放行。IPv4-mapped IPv6 统一转换为 IPv4；因此 `::ffff:192.0.2.8` 不能绕过 `192.0.2.0/24`。本模块自身不查询 IP 地区库。
- 频率接口只接收 `scope`、`subject`、`client_ip`；额外路径、跳转、UA、机器人参数会拒绝。`subject` 必须由受信服务生成，不允许访客任意替换以绕过限制。
- 此版本交付的是 API 管理功能和测试，不含可视化控制台，也未接真实商城。原型不是自动部署服务；生产上线仍需独立安全评审、账号鉴权、内部网络/TLS、备份、负载与失败恢复测试。

## 站点、分流项目与 SEO

每个站点可用不同的站点标识绑定一个或多个项目，同一项目可被多个站点使用。一个 `站点 / 项目 / 渠道` 组合对应一条明确的渠道链接。管理 API 共用管理令牌 + 管理网络保护：

| 方法 / 路径 | JSON / 参数 |
|---|---|
| PUT `/admin/channels/bindings` | `{"site":"shop-br","project":"winter"}` |
| PUT `/admin/channels/links` | `{"site":"shop-br","project":"winter","channel":"email","destination":"/products/coffee","active":true}` |
| GET `/admin/channels/links?site=shop-br` | 列出该站绑定的项目和渠道 |
| GET 或 HEAD `/go/shop-br/winter/email` | 已启用时返回 `302` 和 `Cache-Control: no-store`；未启用或未知时返回 404 |

目的路径只接受当前站点的 `/`、`/products/{slug}` 或 `/collections/{slug}`，不支持任意外部 URL、动态 URL 参数或跨站跳转。站点标识是配置分组，不是域名验证或租户隔离；生产网关须明确配置每个业务域名对应的站点标识及路径。示例目标页面应由商城本身渲染，本模块不会生成商品详情或运营网站。演示仅验证 302 和地址，没有接入真实站点；查询参数不透传。

正常访客和搜索引擎访问相同的公开商品 URL、读取相同的内容。正式部署保留商品页的直接访问，把商品正式 URL（不是渠道 URL）放入 sitemap，并在实际站上验证抓取。地区限制以服务端配送检查为准，不通过拦截公开页面来限制配送。已在站点层统一禁访的地区和代理网络不会因安装此模块而改变可访问性。没有独立的设备分流或机器人名单，防刷按业务操作计数。
