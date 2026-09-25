# 路由策略离线推演工作台 (Routing Policy Rehearsal Workbench)

在**发布前**离线看清前缀策略会放行/拒绝哪些前缀。完全本地，**不连接任何生产设备**。

* **React**：前缀树 + 命中链可视化、规则编辑、遮蔽检查、语义差异（最小见证前缀集）、有序回放、**维护窗口时效例外（时间线 + 语义影响 + 合成命中链）**、FRR 交叉验证
* **FastAPI**：REST API，判定核心用 Python 标准库 **`ipaddress`**；例外状态机由**可注入时钟**驱动
* **PostgreSQL**：邻居、有序规则、不可变配置快照、场景、验证运行、**例外与 append-only 状态历史**（也可用 SQLite 免依赖运行）
* **FRRouting 容器**（router-a / router-b，隔离 bridge）：用 FRR 自己的 prefix-list 匹配器对**快照与当前合成配置**做交叉验证

---

## 1. 语义模型（模拟器）

每条规则 `(seq, prefix, action, ge, le)`，规则按 **seq 升序，首条匹配即终止**：

1. **包含关系**：候选前缀必须是规则基址的子网（`candidate subnet-of base`）；
2. **掩码长度窗口**：`effective_min = ge ?? base_len`，`effective_max = le ?? (ge ?? base_len) : base_len`，即
   * 无 ge/le：精确匹配基址长度；
   * 仅 `le`：窗口 `[base_len, le]`；
   * 仅 `ge`：窗口 `[ge, 32|128]`（Cisco 语义）；
3. 第一个同时满足包含与窗口的规则决定 permit/deny；
4. 都不命中 → 策略的**隐式默认动作**（可配，通常 deny）；
5. **IPv4 与 IPv6 严格隔离**：混合规则在构造/分类时直接报错。

`IPv4Network/IPv6Network` 完成全部地址与掩码计算；引擎与 FRR 的 ge/le 边界一致（见下“FRR 一致性”）。

## 2. 不是文本 diff：最小行为见证集

用户改完规则后，系统计算两个**不可变快照**之间的语义差异，输出**行为发生变化的最小前缀集合**，而不是规则文本差异：

* 前缀空间被精确切分为单元（规则基址边界 + ge/le 长度边界），**全枚举、非采样**；
* 同状态单元用并查集合并成“最大等价区域”（同深度地址相邻 + 跨深度包含且获胜规则/窗口一致），区域被更粗的获胜规则切断时不会跨越；
* 每个发生动作变化的区域给出**一个最浅代表前缀**作为探针，并标注旧/新命中 seq；
* `deny→deny` 只是命中规则换了、转发结果没变，**不会**出现；纯文本改写（如改备注）得到空集。

同时提供**遮蔽分析**：完全遮蔽（永不可达，给出被截获的代表前缀）与部分重叠。

### 三个内置示例（`backend/app/seed.py`，含 before/after 快照与有序探针，可回放）

| 场景 | 说明 | 关键见证 |
|---|---|---|
| **over-permit** 更具体路由误放行 | `192.168.0.0/16 le 24` 过宽，把本应拒绝的 DC /24（如 `192.168.100.0/24`）放了进来；收紧到 `le 23` 并加显式 guard | `192.168.0.0/24`、`192.168.100.0/24` 等 `permit→deny` |
| **reorder** 规则换序 | 宽 `172.16/12 le32 permit` 从 seq 20 换到 seq 5，压过窄 `172.31/16 deny`（后者变完全遮蔽） | `172.31.0.0/16 deny→permit` |
| **default-flip** 默认动作变化 | 删掉 `0/0 permit` 风格兜底、默认从 permit 翻成 deny | `0.0.0.0/0 permit→deny`（最宽代表） |

另含 IPv6 示例 **over-permit-v6**（`2001:db8::/32 le 48` 过宽）。

## 3. 回放：输入与生效次序

* 每次“发布候选”都生成**不可变快照**（含有序规则、默认动作、族、渲染好的 FRR 配置）；
* 场景保存**有序探针列表**，`/api/scenarios/{id}/replay` 以相同顺序对 before/after 两个快照确定性回放，返回每条命中链与差异；
* 快照 payload 自包含，后续再编辑规则不影响历史回放——满足“可回放输入及生效次序”。

## 4. 维护窗口：有时效的策略例外

维护窗口中临时放行/拒绝少量前缀，**窗口结束自动恢复基线**。例外**绝不修改原规则**，而是与基线快照在求值时合成。

**绑定与生命周期** —— 每条例外记录（`policy_exceptions`）绑定：

* **不可变基线快照** `baseline_snapshot_id`（快照 payload 自包含，旧快照永不被覆盖）；
* **地址族**（必须与基线一致，v4/v6 严格隔离）、**匹配范围** `(prefix, ge, le)`、动作 permit/deny、显式**优先级**；
* **起止时间**（半开区间 `[starts_at, ends_at)`：起点时刻生效、终点时刻恢复）、**理由**、请求人/批准人与**审批状态**。

状态机：

```
draft(草稿) → pending(待批准) → planned(已计划) → active(已生效) → expired(已过期)
                  └ reject→rejected→revise→draft      └──────────────> revoked(已撤销)
```

每次迁移写一行 append-only 历史（`exception_events`，含 from/to 状态与边界时刻）。

**重叠合成（确定优先级 + 最终命中链）** —— 合成策略是一个全新引擎 Policy，规则顺序为

```
[生效例外, 按优先级全序排列]  seq 10,20,…   (低 seq 带)
[基线规则, 保持原相对顺序]    seq 1_000_000+原seq  (高 seq 带)
```

FRR/Cisco 的首条匹配即天然实现优先级，**基线规则一行都不改**。重叠例外按明确全序
`priority 降序 → 基址最长(最具体) → ge/le 窗口更窄 → id 升序` 决出唯一胜者；
`/api/exceptions/{id}/preview` 为每对重叠给出交集中的**最小见证前缀**、胜者/败者与是否动作冲突；
`/api/policies/{pid}/effective/classify` 同时返回**例外层命中链**（每条例外的包含/窗口判定与原因）与**完整基线命中链**及最终动作，清楚展示“谁覆盖了谁”。

**幂等与迟到事件** —— 激活、过期、撤销都以存储状态为守卫且历史按 `(例外, 事件类型, 时刻)` 去重：

* 重复 / 乱序投递 activate、expire、revoke 都是无副作用的 no-op，终态不变、历史只有一条；
* 时钟一次性跳过整个窗口时，例外标记 `skipped→expired`，**不会**瞬时激活；窗口结束后的迟到 activate 不能复活旧例外（返回 stale）。

**基线替代后的待复核** —— 对策略打新快照（基线被替代）时，所有**尚未生效**的例外自动置 `needs_review` 并写 `review_required` 事件：它们在重新预览 + 用预览签名确认（`reconfirm`）前不会激活；已生效例外继续按批准时的快照运行至自身窗口结束，旧快照/旧规则不被覆盖。

**定时与重启补跑** —— `backend/app/scheduler.py` 用 FastAPI lifespan 启动，周期性对**可注入时钟**跑幂等 `sweep`，启动即补跑停机期间错过的边界。因此进程重启后补跑过期事件也只产生一次历史记录。时钟可通过 `POST /api/clock {"at":...}` 冻结/`{"reset":true}` 恢复（测试与 UI 演示用）；可用 `RLAB_SWEEP_DISABLED=1` 关闭后台任务。

**只在本地隔离 FRR 验证当前合成配置** —— `POST /api/policies/{pid}/effective/cross-validate` 把**当前时刻的合成配置**渲染成一次性 prefix-list（低 seq 例外带 + 高 seq 基线带）下发到隔离容器，用 FRR 原生匹配逐条比对，结束即删除，基线列表本身不被触碰。

UI 在「⑤ 维护窗口例外」页：可冻结/推进时钟、手动扫描；例外列表内联状态徽标与待复核高亮；详情含 **append-only 时间线**、草稿/提交/批准/驳回/撤销操作、语义影响预览（最小见证 + 重叠裁决）、新基线重新确认，以及合成命中链与合成 FRR 配置查看。

## 5. FRR 容器交叉验证

两个 FRR 8.4 节点在隔离的 internal bridge（`172.30.10.0/24`，无外部连通）上。验证流程（`backend/app/validate.py`）：

1. 把快照渲染成 `ip/ipv6 prefix-list NAME seq N permit/deny PREFIX [ge X] [le Y]` 下发到容器；
2. 对每个探针执行 FRR 原生命令
   `vtysh -c "debug ip prefix-list NAME match PREFIX"`
   —— 输出由 **FRR 自己的匹配代码**给出 `PERMIT/DENY` 与 `matching entry #seq`；
3. 与 `ipaddress` 模拟器逐条比对动作与 seq，结果写入 `runs` 表；
4. 结束后删除该 prefix-list。

FRR 语义已对照其源码 `lib/plist.c` 核对（包含关系、无 ge/le 精确匹配、窗口、首条最小 seq、未命中 DENY）。注意 FRR 对**空** prefix-list 返回 PERMIT，因此空策略会被报为 lab setup error 而非静默一致。

传输默认 `docker exec`（`RLAB_FRR_TRANSPORT=docker`），也可切到 SSH（`RLAB_FRR_TRANSPORT=ssh`，见 `backend/app/config.py`）。容器不在线时相关测试自动 skip，UI 显示离线徽标。

## 6. 快速开始

### 免容器 / 免 Postgres（SQLite，最快体验）

```bash
cd backend
python -m pip install -r requirements.txt
python -m app.seed                       # 建表 + 写入示例（数据在 backend/data/）
python -m uvicorn app.main:app --port 8765
# API 文档 http://127.0.0.1:8765/docs

cd ../frontend
npm install && npm run dev               # http://localhost:5173 （已配 /api 代理）
```

### 完整本地栈（PostgreSQL + FRR）

```bash
docker compose up -d postgres router-a router-b
cd backend
DATABASE_URL=postgresql+psycopg://rlab:rlab@127.0.0.1:5432/rlab \
  python -m app.seed
RLAB_FRR_TRANSPORT=docker python -m uvicorn app.main:app --port 8765
```

在 UI “④ 回放 / FRR 交叉验证”页选快照与节点（router-a / router-b），点“推送 FRR 并比对”，或：

```bash
curl -s localhost:8765/api/frr/status
curl -s -XPOST localhost:8765/api/snapshots/<id>/cross-validate \
  -H 'content-type: application/json' \
  -d '{"probes":["192.168.100.0/24","10.1.2.3/32"],"node":"a"}'
```

## 7. 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

* `test_engine.py`：精确匹配、ge/le 窗口、首条匹配、默认拒绝、v4/v6 隔离、三个示例决策；
* `test_properties.py`：在完整枚举的 /0../6（v4）与 /32../34（v6）格子上，对数百个随机策略用暴力预言机验证**遮蔽判定**与**最小见证集**逐区域一致（非采样）；
* `test_api.py`：编辑→快照→差异→回放的端到端 REST；
* `test_exceptions.py`：时效例外全部验收——边界时刻生效/自动恢复、重叠例外确定结果与最小见证、重复/乱序激活过期的幂等与终态、时钟跳过窗口不复活、撤销幂等、基线替代→待复核→重预览/签名确认（旧快照不覆盖、快照差异/探针回放仍正确）、进程重启补跑只生成一次历史、合成配置对 FRR 行为模型逐条一致；
* `test_frr_consistency.py`：FRR 输出解析、随机 400 例与 FRR `prefix_list_apply` 移植模型逐条一致；`test_live_frr_consistency` 在检测到容器时自动对真实 FRR 运行（例外合成配置同理，见 `test_live_frr_composed_effective_config`）。

## 8. 主要 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/policies` | 策略列表（含规则与渲染的 FRR 配置） |
| PUT | `/api/policies/{id}/rules` | 整表有序替换规则（经 ipaddress 校验、族隔离、ge/le 校验） |
| GET | `/api/policies/{id}/analyze` | 完全/部分遮蔽分析 |
| POST | `/api/policies/{id}/classify` | 单条命中链（含 trie_path、每条规则包含/窗口判定与原因） |
| POST | `/api/policies/{id}/classify/batch` | 批量有序推演（坏输入逐条隔离报错） |
| GET | `/api/policies/{id}/trie` | 前缀树视图 |
| POST | `/api/policies/{id}/snapshots` | 创建不可变快照 |
| POST | `/api/snapshots/diff` | 两个快照的最小见证集差异 |
| POST | `/api/snapshots/{id}/replay` | 有序探针确定性回放 |
| POST | `/api/snapshots/{id}/cross-validate` | 推送 FRR 容器并逐条比对 |
| GET/POST | `/api/scenarios`、`/api/scenarios/{id}/replay` | 场景（输入+两个快照+结果） |
| GET/POST | `/api/neighbors` | 本地实验室邻居 |
| GET | `/api/frr/status`、`/api/runs` | 容器在线状态、历史验证运行 |
| GET/POST | `/api/clock`、`/api/exceptions/sweep/run` | 可注入时钟冻结/恢复；手动补跑定时事件 |
| GET/POST | `/api/policies/{id}/exceptions`、`/api/exceptions/{id}` | 例外列表/创建/详情（含 append-only 事件） |
| POST | `/api/exceptions/{id}/submit` `/approve` `/reject` `/revise` `/activate` `/expire` `/revoke` | 审批与定时生命周期操作（全部幂等、迟到不复活） |
| GET/POST | `/api/exceptions/{id}/preview`、`/api/policies/{id}/exceptions/preview` | 语义影响预览：最小见证 + 重叠裁决（候选可不落库） |
| POST | `/api/exceptions/{id}/reconfirm` | 基线替代后用预览签名重新确认并绑定新快照 |
| GET/POST | `/api/policies/{id}/effective` `/effective/classify` `/effective/cross-validate` | 某时刻合成配置、合成命中链（例外层+基线层）、仅本地 FRR 验证当前合成配置 |

## 目录

```
backend/app/   engine.py(匹配/遮蔽) trie.py(精确单元+最小见证) service.py db.py
               exceptions.py(时效例外纯合成) exception_service.py(状态机/幂等/复核)
               clock.py(可注入时钟) scheduler.py(lifespan 定时补跑)
               validate.py frr_bridge.py treeview.py routers/api.py routers/exceptions.py seed.py
frontend/src/  App.jsx + components/(PolicyEditor/TrieView/DiffView/ReplayLab/Exceptions/Neighbors)
frr/           两个节点的 daemons/vtysh/frr.conf 与独立 docker-compose
tests/         引擎/属性/API/时效例外/FRR 一致性
docker-compose.yml   postgres + backend + router-a/b
```
