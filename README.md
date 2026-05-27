# PipacodeA v1.1.0

基于 [jar-analyzer](https://github.com/jar-analyzer/jar-analyzer) + CodeQL 的 Claude Code 插件，
用于 Java JAR/WAR 包静态分析与安全审计。

## 安装

### 方式一：Git Clone（推荐）

```bash
# 克隆到 Claude Code 插件目录
mkdir -p ~/.claude/plugins
git clone https://github.com/hack-umbrella/PipacodeA.git ~/.claude/plugins/PipacodeA

# 全局配置启用插件（编辑 ~/.claude/settings.json）
{
  "enabledPlugins": {
    "PipacodeA@jar-analyzer-marketplace": true
  },
  "permissions": {
    "allow": [
      "Bash(java *)",
      "Bash(python3 *)",
      "Bash(codeql *)",
      "Bash(sqlite3 *)"
    ]
  }
}
```

### 方式二：Marketplace 安装

在 Claude Code 中运行 `/plugin` → Install Plugin → 搜索 `PipacodeA`

> 如果 marketplace 未收录，请先添加源：`/plugin` → Manage Marketplaces → 添加 `https://github.com/hack-umbrella/PipacodeA.git`

## 功能

- **双引擎统一审计**：jar-analyzer 全局调用图 + CodeQL 精确污点分析，交叉验证降低误报
- **构建分析数据库**：从 JAR/WAR/Class 文件构建 SQLite 数据库，提取类信息、方法调用关系、继承关系等
- **安全审计分析**：基于数据库查询，检测 RCE、SQL 注入、SSRF、反序列化等常见漏洞模式
- **方法调用链追踪**：从危险 sink 回溯到 HTTP 入口，验证漏洞可达性
- **反编译验证**：内置 CFR 反编译器，快速查看可疑代码
- **Spring 组件分析**：自动识别 Controller、Mapping、拦截器等组件
- **认证绕过检测**：自动发现无鉴权保护的 API 端点
- **自定义 CodeQL 规则**：MyBatis 注入、SpEL 注入、Shiro 绕过、Fastjson 反序列化等

## Skills

| Skill | 说明 | 触发方式 |
|:------|:-----|:---------|
| `unified-audit` | **双引擎统一审计**（新增）。jar-analyzer + CodeQL 联合分析 | `/unified-audit` |
| `jar-audit` | Java 安全审计入口。输入 JAR/WAR，自动完成全流程审计 | `/jar-audit` |
| `build-db` | 从 JAR/WAR 文件构建 SQLite 分析数据库 | `/build-db` |
| `do-analyze` | 对分析数据库执行安全审计查询 | `/do-analyze` |
| `jar-audit-agent` | 证据驱动审计引擎（16 向量自动化扫描） | `/jar-audit-agent` |

### 快速开始（推荐）

```
/unified-audit @/path/to/target.jar
```

一条命令完成：jar-analyzer 调用图 → CFR 反编译 → CodeQL 污点分析 → 关联融合 → 报告生成。

### 分步工作流

```
1. /build-db          → 指定 JAR/WAR 文件，构建数据库
2. /unified-audit     → 双引擎统一审计（含 CodeQL）
3. /do-analyze        → 对数据库执行安全分析查询
4. /jar-audit-agent   → 证据驱动的自动化审计
```

### 攻击向量覆盖

RCE / SSTI / SQLi / SSRF / 反序列化 / XSS / XXE / LFI / JNDI / 文件操作 / 认证绕过 / 路径穿越 / 表达式注入 / 日志注入 / 开放重定向 / 视图注入 / CSRF / 弱加密 / 硬编码凭证

### 置信度评分

| 状态 | 含义 |
|:-----|:-----|
| Confirmed | 双引擎共同确认（CodeQL + 调用图可达） |
| Probable | 单引擎发现 + 调用链可达 |
| Possible | 单引擎发现，未验证可达性 |
| Unverified | 仅 CodeQL 发现，无调用链验证 |

## 环境要求

- Java 8+（用于运行分析引擎和反编译）
- Python 3.8+（用于审计引擎）
- CodeQL CLI（`brew install codeql`，用于深度分析）
- sqlite3（用于数据库查询）
- Python 依赖：`pip install PyYAML Jinja2`（仅 jar-audit-agent 需要）

## 致谢

- [jar-analyzer](https://github.com/jar-analyzer/jar-analyzer) — 4ra1n
- [CodeQL](https://github.com/github/codeql) — GitHub
