---
name: jar-audit-agent
description: 证据驱动的 Java 安全审计技能。基于 jar-analyzer SQLite 数据库 + 引擎反编译，实现"结论=可复现证据+可度量覆盖率"的标准化审计流程。支持 16 类攻击向量（RCE/SSTI/SQLi/SSRF/Deser/XSS/XXE 等）的自动化发现、可达性分析、证据采集与报告生成。
---

# jar-audit-agent（Evidence + Coverage 驱动审计）

## 概述

本 skill 将安全审计从"凭经验猜测"升级为"证据驱动的可复现流程"：
- **事实基线**：所有发现必须来自 SQLite DB 查询（可复现、可计数）
- **证据采集**：所有结论必须附带反编译代码切片（sha256 哈希）
- **覆盖率度量**：报告包含 Verified/Emitted/Remaining 指标
- **攻击向量**：16 类向量（RCE/SSTI/SQLi/SSRF/Deser/XSS/XXE/LFI/Auth 等）全覆盖

## 前置条件

- 已使用 `build-db` skill 构建了 `jar-analyzer.db`
- Java 8+ 可用（用于反编译）
- Python 3.8+ 可用（用于审计引擎）
- 依赖已安装：`pip install PyYAML Jinja2`（或 `pip install -r <skill_dir>/scripts/requirements.txt`）

## 关键路径

| 资源 | 路径 |
|:-----|:-----|
| 审计引擎 CLI | `<skill_dir>/scripts/cli.py` |
| 引擎模块 | `<skill_dir>/engine/` |
| 攻击向量定义 | `<skill_dir>/vectors/*.yaml` |
| 默认审计队列 | `<skill_dir>/vectors/default_queue.yaml` |
| 数据库 Schema | `<skill_dir>/references/DATABASE_SCHEMA.md` |
| 策略库 | `<skill_dir>/references/TACTICS_LIBRARY.md` |
| 报告模板 | `<skill_dir>/assets/report_template.md` |
| 严重度标准 | `<skill_dir>/assets/severity_rubric.yaml` |
| 反编译引擎 | `<plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar` |
| Sink 定义 | `<plugin_dir>/references/dfs-sink.json` |
| DB Schema 文档 | `<plugin_dir>/references/DATABASE.md` |

> `<skill_dir>` = 本 skill 目录（包含 `scripts/`、`engine/`、`vectors/`）
> `<plugin_dir>` = 插件根目录（包含 `bin/`、`references/`）

## 反编译取证方式

本 skill 使用 `jar-analyzer-engine-1.2.0.jar --decompile` 获取代码证据：

```bash
# 反编译指定类（输出到控制台，自动保存到文件）
java -jar <plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar \
    -j <target_war_or_jar> \
    -d <fully.qualified.ClassName> \
    > <skill_dir>/runs/<run_id>/inputs/decompile_<class>.txt 2>/dev/null
```

然后用 `evidence` 命令处理反编译输出：
```bash
python <skill_dir>/scripts/cli.py evidence \
    --candidate-id <CID> --batch-id <BID> \
    --code-text-file <skill_dir>/runs/<run_id>/inputs/decompile_<class>.txt \
    --auto-fallback
```

## 操作流程

### 快速审计（单向量）

```bash
cd <skill_dir>

# 1. 初始化
python scripts/cli.py init --db <path/to/jar-analyzer.db>
# 输出: Run ID, Python 命令

# 2. 配置 profile
python scripts/cli.py profile --run <ID> --cwd <plugin_dir>

# 3. 构建调用图
python scripts/cli.py graph --run <ID>

# 4. 冻结某个向量（如 rce）
python scripts/cli.py freeze --run <ID> --vector rce --cwd <plugin_dir>

# 5. 可达性分析
python scripts/cli.py reach --run <ID> --vector rce

# 6. 取下一批候选
python scripts/cli.py next --run <ID> --vector rce --limit 5

# 7. 对每个候选取证
# 7a. 反编译
java -jar <plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar \
    -j <target> -d <ClassName> \
    > runs/<ID>/inputs/decompile_<ClassName>.txt 2>/dev/null

# 7b. 采集证据
python scripts/cli.py evidence --run <ID> \
    --candidate-id <CID> --batch-id <BID> \
    --code-text-file runs/<ID>/inputs/decompile_<ClassName>.txt \
    --auto-fallback

# 8. 提交结论
python scripts/cli.py submit --run <ID> \
    --candidate-id <CID> --batch-id <BID> \
    --status VULN|SAFE|NEEDS_DEEPER

# 9. 循环 6-8 直到无候选
# 10. 生成报告
python scripts/cli.py report --run <ID> --strict
```

### 全量审计（16 向量覆盖）

```bash
cd <skill_dir>

# 初始化
python scripts/cli.py init --db <path/to/jar-analyzer.db>
python scripts/cli.py profile --run <ID> --cwd <plugin_dir>
python scripts/cli.py graph --run <ID>

# 对默认队列中每个向量执行完整循环
# 默认队列: rce → ssti → view → expr → jndi → sqli → xxe → lfi → ssrf → file → deser → reflect → xss → redirect → log → auth

for vector in rce ssti view expr jndi sqli xxe lfi ssrf file deser reflect xss redirect log auth; do
    python scripts/cli.py freeze --run <ID> --vector $vector --cwd <plugin_dir>
    python scripts/cli.py reach --run <ID> --vector $vector

    # VERIFY LOOP
    while true; do
        batch=$(python scripts/cli.py next --run <ID> --vector $vector --limit 5)
        [ -z "$batch" ] && break

        # 对 batch 中每个 candidate:
        #   反编译 → evidence → submit
        # （需要在 Python/循环中解析 batch JSON）
    done
done

# 最终报告
python scripts/cli.py report --run <ID> --strict
```

## 攻击向量说明

| 向量 | 说明 | 关键 Sink |
|:-----|:-----|:----------|
| rce | 远程代码执行 | Runtime.exec, ProcessBuilder.start, ScriptEngine.eval |
| ssti | 模板注入 | FreeMarker, SpEL, OGNL, JEXL, MVEL, Velocity |
| jndi | JNDI 注入 | InitialContext.lookup, Context.lookup |
| sqli | SQL 注入 | Statement.execute, Connection.prepareStatement |
| ssrf | 服务端请求伪造 | URL.openConnection, HttpURLConnection.connect |
| deser | 反序列化 | ObjectInputStream.readObject, JSON.parseObject, XStream.fromXML |
| xxe | XML 外部实体 | SAXReader, DocumentBuilder |
| lfi | 本地文件包含 | FileInputStream, File.read |
| file | 文件操作 | FileOutputStream, File.delete |
| xss | 跨站脚本 | response.getWriter().print |
| redirect | 开放重定向 | response.sendRedirect |
| reflect | 反射调用 | Method.invoke, Class.forName |
| expr | 表达式注入 | SpEL, OGNL, MVEL |
| log | 日志注入 | log.info/error(user_input) |
| auth | 认证绕过 | 缺失注解的 Controller 方法 |
| view | 视图解析 | ViewResolver, setViewName |

## 禁止事项

- **禁止手写 Python 脚本**解析 curl/HTTP 输出 — 只用 `scripts/cli.py`
- **禁止手写 curl/HTTP 调用** — 取证只走 `--decompile` 命令
- **禁止 grep 从反编译输出抽代码** — 必须用 `evidence --code-text-file`
- **禁止猜路径** — 取证只用已知路径
- **遇到工具不支持时必须停下** — 输出"需要扩展 skill"

## 铁律

- **Fact**：方法节点 = 四元组 `(jar_id, class, method, desc)` — 禁止只用名字 join
- **Evidence**：submit 必须带 `snippet_ref` 或 `chain_trace` 或 `sql_proof` — 否则拒绝写入
- **Report**：报告只读 artifacts 编译；`--strict` 未完成 coverage 直接 fail

## 状态机

```
init → profile → graph → [freeze → reach → next → evidence → submit]* → report
```

每个向量独立循环，直到：
- 该向量无可取候选（next 返回空）
- 或所有候选已提交为 final（VULN/SAFE）
- 或剩余全部标记为 NEEDS_DEEPER

## 报告输出

报告生成在 `runs/<ID>/artifacts/audit_report.md`，包含：
- 漏洞清单（VULN）及证据引用
- 安全清单（SAFE）及排除原因
- 待深入清单（NEEDS_DEEPER）及阻断原因
- 覆盖率统计（Verified/Emitted/Remaining）
- Remaining TopK（下一批计划）

## 注意事项

- 首次运行需安装 Python 依赖：`pip install PyYAML Jinja2`
- 反编译输出可能很大（>1MB），建议重定向到文件
- 大型数据库（>50MB）的 graph 构建可能需要几分钟
- `--strict` 模式下，覆盖率未达标会直接 fail
