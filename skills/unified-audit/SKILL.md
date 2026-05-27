---
name: unified-audit
description: jar-analyzer + CodeQL 双引擎统一安全审计。自动完成数据采集→深度分析→关联融合的完整流程，通过调用图可达性验证和污点分析交叉确认，实现高精度、低误报的漏洞发现。支持 RCE/SQLi/SSRF/XSS/XXE/Deser/AuthBypass 等 16+ 攻击向量。
---

# unified-audit（双引擎统一安全审计）

## 概述

将 jar-analyzer 的全局调用图分析与 CodeQL 的精确污点追踪整合为统一审计流水线：
- **Phase 1**: 并行数据采集（jar-analyzer 构建调用图 + CFR 反编译源码）
- **Phase 2**: 双引擎分析（jar-analyzer Sink 扫描 + CodeQL 安全查询）
- **Phase 3**: 关联融合（可达性验证 + 置信度评分 + 去重）

核心优势：两个引擎互相验证 — CodeQL 的发现通过调用图验证可达性，jar-analyzer 的 Sink 通过污点分析验证真实性。

## 前置条件

- Java 8+（jar-analyzer-engine + CFR 反编译）
- Python 3.8+
- CodeQL CLI（`brew install codeql` 或从 GitHub 下载）
- CodeQL Java Query Pack（`codeql pack download codeql/java-queries`）
- 已安装 `codeql/java-all`（`codeql pack download codeql/java-all`）

## 关键路径

| 资源 | 路径 |
|:-----|:-----|
| 审计引擎 | `<skill_dir>/engine/unified_audit.py` |
| CLI 入口 | `<skill_dir>/scripts/cli.py` |
| 扩展 Schema | `<skill_dir>/engine/schema.sql` |
| 自定义 QL 规则 | `<skill_dir>/codeql-queries/custom/*.ql` |
| 反编译引擎 | `<plugin_dir>/bin/jar-analyzer-engine-1.2.0.jar` |
| Sink 定义 | `<plugin_dir>/references/dfs-sink.json` |
| DB Schema 文档 | `<plugin_dir>/references/DATABASE.md` |

> `<skill_dir>` = 本 skill 目录（包含 `engine/`、`scripts/`、`codeql-queries/`）
> `<plugin_dir>` = 插件根目录（包含 `bin/`、`references/`）

## 操作流程

### 完整审计（推荐）

一条命令完成全部三个阶段：

```bash
cd <skill_dir>
python scripts/cli.py run --jar <target.jar> --work-dir <output_dir>
```

输出：
- `<output_dir>/jar-analyzer.db` — 扩展后的 SQLite 数据库（含 CodeQL 结果 + 关联数据）
- `<output_dir>/unified_audit_report.md` — 统一审计报告
- `<output_dir>/codeql-db/` — CodeQL 数据库
- `<output_dir>/decompiled/` — 反编译的 Java 源文件

### 分阶段执行

#### Phase 1: 仅数据采集

```bash
python scripts/cli.py collect --jar <target.jar> --work-dir <output_dir>
```

产出：jar-analyzer.db + 反编译源码

#### Phase 2a: 仅 CodeQL 分析

```bash
python scripts/cli.py codeql --work-dir <output_dir>
```

产出：CodeQL 发现 JSON

#### Phase 2b: 仅 jar-analyzer Sink 扫描

```bash
python scripts/cli.py scan --db <jar-analyzer.db> --jar <target.jar>
```

产出：Sink 列表 + Spring 路由 + 认证缺口

#### Phase 3: 仅关联融合

```bash
python scripts/cli.py correlate --work-dir <output_dir>
```

产出：统一漏洞发现

## 数据库查询示例

审计完成后，可直接查询 `jar-analyzer.db` 中的统一发现：

```sql
-- 查看所有已确认的高危漏洞
SELECT vuln_type, severity, title, class_name, method_name,
       overall_confidence, verification_status, ja_entry_path
FROM unified_findings
WHERE verification_status = 'confirmed'
ORDER BY overall_confidence DESC;

-- 按漏洞类型统计
SELECT vuln_type, COUNT(*) as count, 
       AVG(overall_confidence) as avg_confidence
FROM unified_findings
GROUP BY vuln_type
ORDER BY count DESC;

-- 查看某个漏洞的完整调用链
SELECT uf.title, uf.class_name, uf.method_name,
       jc.entry_path, jc.chain, jc.chain_depth
FROM unified_findings uf
LEFT JOIN ja_call_chains jc ON uf.ja_cc_id = jc.cc_id
WHERE uf.vuln_type = 'sqli';

-- 查看认证缺口（无鉴权的 Controller 方法）
SELECT class_name, method_name, ja_entry_path
FROM unified_findings
WHERE vuln_type = 'auth_bypass'
ORDER BY ja_entry_path;

-- 查看 CodeQL 原始发现
SELECT vuln_type, source_class, source_method, source_file, source_line
FROM codeql_findings
WHERE severity IN ('critical', 'high')
ORDER BY severity, vuln_type;

-- 查看框架指纹
SELECT framework, version, known_cves
FROM framework_fingerprints
WHERE known_cves IS NOT NULL;

-- 综合报告：漏洞 × 入口 × 可达性
SELECT 
    uf.vuln_type,
    uf.severity,
    uf.verification_status,
    ROUND(uf.overall_confidence * 100) || '%' as confidence,
    jvm_to_dot(uf.class_name) as class_name,
    uf.method_name,
    COALESCE(jc.entry_path, 'N/A') as entry_point,
    COALESCE(jc.chain_depth, 0) as chain_depth
FROM unified_findings uf
LEFT JOIN ja_call_chains jc ON uf.ja_cc_id = jc.cc_id
WHERE uf.overall_confidence >= 0.5
ORDER BY uf.overall_confidence DESC;
```

## 置信度评分机制

| 来源 | 基础分 | 条件 | 最终分 | 状态 |
|:-----|:-------|:-----|:-------|:-----|
| CodeQL + jar-analyzer 共同确认 | 0.8 | 调用链可达 | 0.9+ | confirmed |
| CodeQL 单独发现 | 0.8 | 无调用链验证 | 0.4 | unverified |
| jar-analyzer Sink 单独发现 | 0.5 | 调用链可达 | 0.5 | probable |
| 认证缺口 | 0.7 | — | 0.7 | probable |

## 自定义 QL 规则

内置的自定义 CodeQL 规则（`<skill_dir>/codeql-queries/custom/`）：

| 规则 | ID | 说明 |
|:-----|:---|:-----|
| MyBatis SQL 注入 | java/mybatis-sql-injection | 检测 ${} 字符串拼接 |
| Spring SpEL 注入 | java/spel-injection-custom | 用户输入流入 SpEL 表达式 |
| Shiro 认证绕过 | java/shiro-auth-bypass | 路径穿越绕过认证 |
| Fastjson 反序列化 | java/fastjson-deserialization | autoType 开启风险 |
| Actuator 未授权 | java/spring-actuator-exposed | Actuator 端点暴露 |

## 注意事项

- CodeQL 分析需要几分钟，大型项目可能更长
- 反编译后的源码与原始源码可能存在差异，行号仅供参考
- 置信度评分为自动计算，建议对 critical/high 级别进行人工确认
- 首次运行会自动下载 CFR 反编译器（约 2MB）
- CodeQL 数据库和 jar-analyzer.db 是独立的，扩展表添加在 jar-analyzer.db 中
