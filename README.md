# LXe 配置包门限签封服务（lxe-config-seal）

液氙探测器上线脚本前的配置包门限签封服务。运行组登记的 **2–8 个唯一 P-256
公钥** 与门限共同构成签封组；配置包只有在集齐足额有效审查签名、并且精确
接续当前已确认链头时才会被确认，从而保证任何时刻只有**一条**有效的配置
历史——重试与并发提交都无法制造分叉。

## 签名与摘要的规范字节序列

审查签名覆盖如下拼接的规范 UTF-8 字节序列（ECDSA / P-256 / SHA-256）：

```
DOMAIN_SEPARATOR("LXe-ConfigSeal/v1") || 0x00
|| uint16BE(len(group_id)) || group_id          (UTF-8)
|| prev_digest                                   (32 字节原始值)
|| uint64BE(seq)
|| config                                        (UTF-8)
```

包的确认摘要 `digest = SHA-256(上述字节序列)`（hex）。首包的
`prev_digest` 为 64 个 `'0'`（创世前序）。签名接受 DER 或 64 字节
`r||s` 的 hex 编码；公钥登记接受压缩/未压缩 SEC1 hex 或 PEM，非 P-256
曲线一律拒绝。审查员以其公钥压缩 SEC1 编码的 SHA-256 指纹（`key_id`）
标识。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查（Docker HEALTHCHECK 与 Compose 均使用） |
| POST | `/v1/groups` | 建立签封组：`{group_id, threshold, public_keys[2..8]}` → 201 |
| GET | `/v1/groups/{gid}` | 组信息与当前唯一链头 `{seq, digest}` |
| GET | `/v1/groups/{gid}/packages` | 已确认配置包列表（审计） |
| POST | `/v1/groups/{gid}/packages` | 提交配置包 → 201（确认）/ 200（幂等重放） |

提交配置包请求体：

```json
{
  "op_id": "deploy-2026-09-26-001",          // 稳定操作标识（幂等键）
  "prev_digest": "00…00",                     // 所见前序摘要（必须等于当前链头）
  "seq": 1,                                   // 连续序号（必须为 head.seq + 1）
  "config": "field=1500V\ndrift=…",           // 配置文本（UTF-8，≤1MiB）
  "signatures": [{"key_id": "…", "signature": "…"}, …]
}
```

确认响应：`{group_id, seq, digest, prev_digest, op_id, signers, replay}`。

### 拒绝语义（均不改变历史）

| 情形 | 状态码 / `error` |
|---|---|
| 公钥数量越界、重复公钥、非 P-256、门限越界 | 400 `bad_key_count` / `duplicate_key` / `bad_key` / `bad_threshold` |
| 重复签署者 | 422 `duplicate_signer` |
| 未登记签署者 | 422 `unknown_signer` |
| 门限不足 | 422 `insufficient_threshold` |
| 无效签名（含篡改、签错字段） | 422 `invalid_signature` |
| 过期前序 / 序号不连续 / 竞争中落败 | 409 `stale_predecessor` |
| 同一 `op_id` 改换载荷 | 409 `op_id_conflict` |
| 重复组建组 | 409 `group_exists` |

### 原子性与恢复

- 确认过程在**同一个 SQLite `BEGIN IMMEDIATE` 事务**内完成：幂等回执查找
  → 当前链头校验 → 写入配置包 → 写入幂等回执 → 条件化移动链头
  （`UPDATE heads … WHERE head_seq=? AND head_digest=?`，并以
  `UNIQUE(group_id, seq)` 兜底）。竞争同一前序的请求至多一个成功。
- 同一 `op_id` + 相同载荷重传：返回 200 与已存回执（`replay: true`），
  不产生新历史；相同 `op_id` + 不同载荷：409 冲突。只有**已确认**的包
  才留下回执，校验失败的尝试不会占用 `op_id`。
- 重启后服务从 `packages` 表中已确认记录**重建唯一链头**
  （日志输出 `recovered chain head: …`），随后即可继续续包。

## 运行

### Docker Compose（推荐）

```bash
# 构建 + 启动服务 + 运行 verify 验收（门限不足 / 幂等重传 / 链头竞争），
# verify 的退出码即整条命令的退出码：
docker compose up --build --exit-code-from verify --abort-on-container-exit

# 仅启动服务，宿主端口可配置（默认 8080）：
SEAL_HOST_PORT=9090 docker compose up -d seal
curl http://127.0.0.1:9090/healthz
```

- `seal` 服务：数据持久化在命名卷 `seal-data`（容器内 `/data/seal.db`），
  自带健康检查。
- `verify` 服务：等待 `seal` 健康后执行 `scripts/verify.py`——健康/构建
  冒烟、组建组、门限不足拒绝、篡改签名拒绝、有效首包（摘要/序号/唯一链头
  校验）、幂等重传、`op_id` 冲突、8 路并发分叉（恰好一个赢家）——全部
  通过退出 0，否则退出 1。

### Dockerfile 单独使用

```bash
docker build -t lxe-config-seal .
docker run -e SEAL_PORT=8080 -p 8080:8080 -v seal-data:/data lxe-config-seal
```

环境变量：`SEAL_HOST`（默认 `0.0.0.0`）、`SEAL_PORT`（默认 `8080`）、
`SEAL_DB`（默认 `/data/seal.db`）、`SEAL_LOG_LEVEL`。

### 本地开发

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
SEAL_HOST=127.0.0.1 SEAL_PORT=8080 SEAL_DB=./seal.db .venv/bin/python -m app
.venv/bin/python -m pytest tests/ -q        # 16 项验收测试
SEAL_TARGET_PORT=8080 .venv/bin/python scripts/verify.py
```

## 测试覆盖（tests/test_seal.py，全部使用临时生成的 P-256 测试密钥）

建组参数校验（数量/重复/非 P-256/门限/重复组）、有效首包与续包的摘要·
序号·唯一链头、篡改签名、签错字段、重复签署者、未知签署者、门限不足、
过期前序（重放旧前序与跳号）、幂等重传、`op_id` 冲突、8 线程并发分叉
（恰好一个确认）、重启后链头恢复并继续续包、HTTP 端到端冒烟。

## 布局

```
app/
  crypto.py    规范字节序列、摘要、P-256 密钥/签名原语
  store.py     SQLite 持久化：单事务确认、幂等回执、链头重建
  service.py   校验与编排（无状态校验 → 单事务提交）
  server.py    标准库 HTTP 层
  __main__.py  入口（env 配置、SIGTERM 优雅关闭）
scripts/verify.py   Compose verify 服务的验收脚本
tests/              pytest 验收套件
Dockerfile / docker-compose.yml / requirements*.txt
```
