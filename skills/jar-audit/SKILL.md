---
name: jar-audit
description: Java 项目安全审计唯一入口。输入 JAR/WAR 文件，自动完成数据库构建、16 向量漏洞扫描、反编译取证、证据链生成、报告输出。覆盖 RCE/SSTI/SQLi/SSRF/Deser/XSS/XXE/LFI/Auth 等全部攻击面。
---

# jar-audit — Java 安全审计（唯一入口）

## 使用方式

```
/jar-audit @/path/to/target.war
/jar-audit @/path/to/target.jar
/jar-audit @/path/to/classes/          # 包含 class 文件的目录
/jar-audit @/path/to/jar-analyzer.db   # 已有数据库，跳过构建
```

## 概述

本 skill 是 Java 项目安全审计的**唯一入口**。给定一个 JAR/WAR 文件，自动执行：

1. **构建数据库** — 静态分析字节码，生成 SQLite 分析数据库
2. **目标画像** — 分析技术栈、入口面、依赖规模
3. **16 向量漏洞扫描** — RCE/SSTI/SQLi/SSRF/Deser/XSS/XXE/LFI/Auth 等
4. **可达性分析** — 从 HTTP 入口到 sink 的最短调用链
5. **反编译取证** — 对每个候选取证，生成代码切片
6. **生成报告** — 含漏洞清单、证据引用、覆盖率统计

## 环境要求

- Java 8+（用于 jar-analyzer-engine 反编译）
- Python 3.8+（用于审计引擎）
- sqlite3（用于数据库查询）
- Python 依赖：`pip install PyYAML Jinja2`

## 路径约定

| 资源 | 路径 |
|:-----|:-----|
| 反编译引擎 | `<plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar` |
| Sink 定义 | `<plugin_dir>/references/dfs-sink.json` |
| DB Schema | `<plugin_dir>/references/DATABASE.md` |
| 审计引擎 CLI | `<skill_dir>/../jar-audit-agent/scripts/cli.py` |
| 攻击向量 | `<skill_dir>/../jar-audit-agent/vectors/` |
| 报告模板 | `<skill_dir>/../jar-audit-agent/assets/` |

> `<plugin_dir>` = 包含 `bin/`、`references/`、`skills/` 的插件根目录
> `<skill_dir>` = 本 skill 目录

---

## 执行流程

### Phase 0: 环境检查

```bash
# 检查 Java
java -version

# 检查 Python
python3 --version

# 检查 sqlite3
sqlite3 --version

# 检查 Python 依赖
python3 -c "import yaml, jinja2" 2>/dev/null || pip3 install --break-system-packages PyYAML Jinja2
```

### Phase 1: 构建数据库

**如果输入是 `.db` 文件，跳过此步骤，直接进入 Phase 2。**

```bash
# 完整分析（推荐，适合安全审计）
java -jar <plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar \
    -j <target_path> \
    --inner-jars

# 快速分析（仅方法调用关系，速度更快）
java -jar <plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar \
    -j <target_path> \
    --inner-jars -q
```

**参数选择指南**：

| 场景 | 参数 |
|:-----|:-----|
| Spring Boot FatJar | `--inner-jars` |
| 普通 WAR | 无额外参数 |
| 只关心特定包 | `-w "com/example/app"` |
| 排除第三方库 | `-b "org/apache,com/google"` |
| 速度优先 | `-q`（跳过继承/字符串/Spring 分析） |

**输出确认**：
- 数据库文件：`jar-analyzer.db`（当前目录）
- 关注：`totalClass`、`totalMethod`、`totalCall`、`Progress: 100%`

### Phase 2: 初始化审计引擎

```bash
cd <skill_dir>/../jar-audit-agent

# 初始化审计会话
python3 scripts/cli.py init
# 输出: Run ID = <YYYYMMDD-HHMMSS>

# 配置 profile（分析目标概况）
python3 scripts/cli.py profile --run <RUN_ID> --db <db_path> --cwd <plugin_dir>

# 构建调用图（每个 run 只需一次）
python3 scripts/cli.py graph --run <RUN_ID> --db <db_path>
```

**profile 输出包含**：
- Spring Controller 数量和端点列表
- JavaWeb 组件（Servlet/Filter/Listener）
- JAR 文件列表
- 应用包名前缀猜测
- 入口面统计

### Phase 3: 16 向量自动化审计

**默认队列**（按优先级排序）：
```
rce → ssti → view → expr → jndi → sqli → xxe → lfi → ssrf → file → deser → reflect → xss → redirect → log → auth
```

**对每个向量执行完整循环**：

```bash
cd <skill_dir>/../jar-audit-agent

for VECTOR in rce ssti view expr jndi sqli xxe lfi ssrf file deser reflect xss redirect log auth; do

    # 3a. 冻结（枚举所有 sink 调用者）
    python3 scripts/cli.py freeze --run <RUN_ID> --vector $VECTOR --db <db_path> --cwd <plugin_dir>

    # 3b. 可达性分析（从 HTTP 入口到 sink 的最短链）
    python3 scripts/cli.py reach --run <RUN_ID> --vector $VECTOR --db <db_path>

    # 3c. 验证循环（批次处理）
    while true; do
        # 取下一批候选（默认 5 个）
        BATCH_OUTPUT=$(python3 scripts/cli.py next --run <RUN_ID> --vector $VECTOR --limit 5)

        # 如果没有更多候选，退出循环
        echo "$BATCH_OUTPUT" | grep -q "no candidates\|0 candidates\|empty" && break

        # 解析 batch 文件路径和 candidate IDs
        BATCH_FILE=$(echo "$BATCH_OUTPUT" | grep "batch" | head -1)
        # ... 解析并处理每个 candidate ...

        # 对每个 candidate:
        #   1. 反编译（Phase 4）
        #   2. 采集证据（Phase 4）
        #   3. 提交结论（Phase 4）
    done
done
```

**循环终止条件**（满足任一即可）：
- `next` 返回空/无可取候选
- 所有候选已提交为 final（VULN/SAFE）
- 剩余全部标记为 NEEDS_DEEPER

### Phase 4: 反编译取证与提交

**对每个候选取证**：

```bash
cd <skill_dir>/../jar-audit-agent

# 4a. 反编译（从 candidate 中提取类名）
# 类名格式转换：com/example/MyClass → com.example.MyClass
CLASS_NAME_DOT=$(echo "$CLASS_NAME_SLASH" | tr '/' '.')

java -jar <plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar \
    -j <target_path> \
    -d "$CLASS_NAME_DOT" \
    > runs/<RUN_ID>/inputs/decompile_${CLASS_NAME_SLASH//\//_}.txt 2>/dev/null

# 4b. 采集证据（自动切片 + 质量评估）
python3 scripts/cli.py evidence --run <RUN_ID> \
    --vector $VECTOR \
    --candidate-id "$CANDIDATE_ID" \
    --batch-id "$BATCH_ID" \
    --code-text-file "runs/<RUN_ID>/inputs/decompile_${CLASS_NAME_SLASH//\//_}.txt" \
    --auto-fallback

# 4c. 提交结论
# 根据反编译代码判断：
#   - VULN           — 确认可利用（有明确的数据流从用户输入到 sink）
#   - SAFE           — 确认不可利用（有过滤/白名单/不可达）
#   - NEEDS_DEEPER   — 需要进一步分析

python3 scripts/cli.py submit --run <RUN_ID> \
    --vector $VECTOR \
    --candidate-id "$CANDIDATE_ID" \
    --batch-id "$BATCH_ID" \
    --status VULN|SAFE|NEEDS_DEEPER \
    --reasoning "TAINT: source=... sink=... path=... WHY_SAFE/RISK_NOTE: ..."
```

**证据质量要求**：
- `VULN`（严格模式）：必须有 `snippet_ref`（quality=GOOD）或绑定入口的 `chain_trace`
- `SAFE`：必须有 `snippet_ref` 或 `chain_trace` 或 `sql_proof`
- `NEEDS_DEEPER`：需要说明阻断原因

**判断指南**：

| 情况 | 结论 | reasoning 模板 |
|:-----|:-----|:---------------|
| 用户输入直接到 sink | VULN | `TAINT: source=user_input sink=<sink> path=direct` |
| 有过滤但可能绕过 | NEEDS_DEEPER | `TAINT: source=user_input sink=<sink> path=indirect RISK_NOTE: filter exists but bypass unclear` |
| 常量/硬编码到 sink | SAFE | `TAINT: source=const sink=<sink> path=direct WHY_SAFE: hardcoded value` |
| DB 数据到 sink | SAFE + NOTE | `TAINT: source=db sink=<sink> path=indirect WHY_SAFE: not user-controllable RISK_NOTE: if attacker can write DB, may escalate` |
| 不可达（无入口到此方法） | SAFE | `TAINT: source=unknown sink=<sink> WHY_SAFE: no entry point reaches this method` |

### Phase 5: 生成报告

```bash
cd <skill_dir>/../jar-audit-agent

# 生成报告（严格模式：覆盖率未达标会提示）
python3 scripts/cli.py report --run <RUN_ID> --strict

# 查看进度
python3 scripts/cli.py status --run <RUN_ID>
```

**报告输出位置**: `runs/<RUN_ID>/audit_report.md`

**报告包含**：
- 漏洞清单（VULN）及证据引用（sha256 哈希）
- 安全清单（SAFE）及排除原因
- 待深入清单（NEEDS_DEEPER）及阻断原因
- 覆盖率统计（Verified / Emitted / Remaining）
- Remaining TopK（下一批计划）
- PoC 提示（HTTP raw, SIMULATED）

---

## 输出

| 产出 | 位置 | 说明 |
|:-----|:-----|:-----|
| SQLite 数据库 | `jar-analyzer.db` | 含类/方法/调用图/字符串/Spring 信息 |
| 审计报告 | `runs/<RUN_ID>/audit_report.md` | 结构化漏洞报告 |
| 证据切片 | `runs/<RUN_ID>/evidence/snippets/` | 反编译代码切片（sha256 哈希） |
| 验证记录 | `runs/<RUN_ID>/verify/` | 每个向量的 VULN/SAFE/NEEDS_DEEPER 记录 |
| 候选列表 | `runs/<RUN_ID>/candidates/` | 每个向量的候选方法列表 |
| 调用图缓存 | `runs/<RUN_ID>/graph_cache/` | 可达性分析缓存 |

---

## 快速审计模式（单向量）

如果只关心特定漏洞类型，可以只跑单个向量：

```bash
cd <skill_dir>/../jar-audit-agent

python3 scripts/cli.py init
RUN_ID=<从 init 输出获取>

python3 scripts/cli.py profile --run $RUN_ID --db <db_path> --cwd <plugin_dir>
python3 scripts/cli.py graph --run $RUN_ID --db <db_path>

# 只跑 RCE 向量
python3 scripts/cli.py freeze --run $RUN_ID --vector rce --db <db_path> --cwd <plugin_dir>
python3 scripts/cli.py reach --run $RUN_ID --vector rce --db <db_path>

# 验证循环
python3 scripts/cli.py next --run $RUN_ID --vector rce --limit 5
# ... 反编译 → evidence → submit ...

python3 scripts/cli.py report --run $RUN_ID
```

---

## 注意事项

- 数据库已存在时跳过 Phase 1，直接进入 Phase 2
- 大型项目（>50MB 数据库）的 graph 构建可能需要几分钟
- 反编译输出可能很大（>1MB），建议重定向到文件
- `--strict` 模式下覆盖率未达标会提示，但不会阻止报告生成
- 每个向量独立循环，不要跳过向量
- 证据切片以 sha256 哈希命名，相同代码不会重复存储
