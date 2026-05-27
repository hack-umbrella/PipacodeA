-- Unified Audit Extended Schema
-- Adds CodeQL findings, correlation, and confidence scoring to jar-analyzer.db

-- CodeQL 查询执行记录
CREATE TABLE IF NOT EXISTS codeql_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    db_path TEXT NOT NULL,                    -- CodeQL 数据库路径
    query_pack TEXT NOT NULL,                 -- 使用的查询包
    query_count INTEGER NOT NULL,             -- 执行的查询数量
    finding_count INTEGER NOT NULL,           -- 发现数量
    started_at TIMESTAMP NOT NULL,
    finished_at TIMESTAMP,
    status TEXT DEFAULT 'running'             -- running, completed, failed
);

-- CodeQL 原始发现
CREATE TABLE IF NOT EXISTS codeql_findings (
    cf_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES codeql_runs(run_id),
    query_id TEXT NOT NULL,                   -- QL 规则 ID (如 java/sql-injection)
    query_name TEXT NOT NULL,                 -- 规则名称
    cwe_id TEXT,                              -- CWE 编号
    vuln_type TEXT NOT NULL,                  -- 漏洞分类 (sqli, rce, ssrf, xss, deser, lfi, log_injection, crypto, csrf)
    severity TEXT NOT NULL,                   -- critical, high, medium, low, info
    message TEXT NOT NULL,                    -- 规则描述信息

    -- 位置信息 (CodeQL 格式: 包名.类名)
    source_class TEXT,                        -- 源码类名 (dot 格式)
    source_method TEXT,
    source_file TEXT,                         -- 源文件路径
    source_line INTEGER,
    source_col INTEGER,

    -- Sink 信息
    sink_class TEXT,
    sink_method TEXT,
    sink_file TEXT,
    sink_line INTEGER,
    sink_col INTEGER,

    -- 污点路径 (JSON 数组)
    taint_path TEXT,

    -- 原始 SARIF 数据
    sarif_rule_id TEXT,
    sarif_level TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- jar-analyzer 调用链验证结果
CREATE TABLE IF NOT EXISTS ja_call_chains (
    cc_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cf_id INTEGER NOT NULL REFERENCES codeql_findings(cf_id),

    -- 入口点 (HTTP)
    entry_class TEXT NOT NULL,                -- Controller 类名 (JVM 格式)
    entry_method TEXT NOT NULL,
    entry_path TEXT,                          -- HTTP 路径
    entry_http_method TEXT,                   -- GET/POST/PUT/DELETE

    -- 完整调用链 (JSON 数组)
    -- [{caller_class, caller_method, callee_class, callee_method, jar_name, in_app}]
    chain TEXT NOT NULL,
    chain_depth INTEGER NOT NULL,             -- 调用链深度
    app_class_count INTEGER,                  -- 链中应用类数量
    dep_class_count INTEGER,                  -- 链中依赖类数量

    -- 验证结果
    is_reachable INTEGER NOT NULL DEFAULT 0,  -- 0=不可达, 1=可达
    reachability_score REAL,                  -- 可达性评分 0-1

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 统一漏洞发现 (融合结果)
CREATE TABLE IF NOT EXISTS unified_findings (
    uf_id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- 基本信息
    vuln_type TEXT NOT NULL,                  -- sqli, rce, ssrf, xss, deser, lfi, log_injection, crypto, csrf, auth_bypass
    severity TEXT NOT NULL,                   -- critical, high, medium, low
    cwe_id TEXT,
    title TEXT NOT NULL,
    description TEXT,

    -- 位置 (JVM 格式)
    class_name TEXT NOT NULL,                 -- com/example/MyClass
    method_name TEXT NOT NULL,
    method_desc TEXT,
    source_file TEXT,
    line_number INTEGER,

    -- CodeQL 侧数据
    codeql_cf_id INTEGER REFERENCES codeql_findings(cf_id),
    codeql_confidence REAL,                   -- CodeQL 置信度 0-1
    codeql_taint_path TEXT,                   -- JSON

    -- jar-analyzer 侧数据
    ja_cc_id INTEGER REFERENCES ja_call_chains(cc_id),
    ja_entry_path TEXT,                       -- HTTP 入口路径
    ja_call_chain TEXT,                       -- JSON: 完整调用链
    ja_reachable INTEGER,                     -- 是否可达
    ja_spring_route TEXT,                     -- Spring 路由

    -- 融合评分
    overall_confidence REAL NOT NULL,         -- 综合置信度 0-1
    verification_status TEXT NOT NULL,        -- confirmed, probable, possible, unverified
    exploit_hint TEXT,                        -- 利用提示
    code_snippet TEXT,                        -- 关键代码片段
    poc_template TEXT,                        -- PoC 模板

    -- 证据
    evidence_hash TEXT,                       -- 代码片段 SHA256

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Source-Sink 配对
CREATE TABLE IF NOT EXISTS source_sink_pairs (
    ss_id INTEGER PRIMARY KEY AUTOINCREMENT,
    uf_id INTEGER NOT NULL REFERENCES unified_findings(uf_id),

    source_type TEXT NOT NULL,                -- http_param, cookie, header, request_body, mq, file, config
    source_class TEXT,
    source_method TEXT,
    source_param TEXT,                        -- 参数名

    sink_type TEXT NOT NULL,                  -- sql, command, http, reflection, deser, file_write, ldap, xss
    sink_class TEXT,
    sink_method TEXT,

    -- 传播信息 (JSON)
    sanitizers TEXT,                          -- 经过的清理函数列表
    propagators TEXT,                         -- 传播函数列表
    propagation_length INTEGER               -- 传播链长度
);

-- 框架指纹
CREATE TABLE IF NOT EXISTS framework_fingerprints (
    ff_id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework TEXT NOT NULL,                  -- spring, shiro, fastjson, mybatis, jackson, struts
    artifact TEXT,                            -- 组件名
    version TEXT,
    detection_method TEXT,                    -- class_name, string_match, pom_parse
    known_cves TEXT,                          -- JSON: 已知 CVE 列表
    jar_name TEXT,
    jar_id INTEGER REFERENCES jar_table(jid)
);

-- 认证/授权配置
CREATE TABLE IF NOT EXISTS auth_config (
    ac_id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_type TEXT NOT NULL,                -- filter, interceptor, annotation, xml_config, spring_security
    class_name TEXT,
    method_name TEXT,
    url_pattern TEXT,                         -- URL 模式
    auth_requirement TEXT,                    -- authenticated, role_based, permit_all, deny_all
    roles TEXT,                               -- JSON: 允许的角色
    source_file TEXT,
    jar_id INTEGER REFERENCES jar_table(jid)
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_codeql_findings_vuln_type ON codeql_findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_codeql_findings_severity ON codeql_findings(severity);
CREATE INDEX IF NOT EXISTS idx_codeql_findings_class ON codeql_findings(source_class);
CREATE INDEX IF NOT EXISTS idx_ja_call_chains_cf_id ON ja_call_chains(cf_id);
CREATE INDEX IF NOT EXISTS idx_ja_call_chains_reachable ON ja_call_chains(is_reachable);
CREATE INDEX IF NOT EXISTS idx_unified_findings_vuln_type ON unified_findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_unified_findings_severity ON unified_findings(severity);
CREATE INDEX IF NOT EXISTS idx_unified_findings_confidence ON unified_findings(overall_confidence);
CREATE INDEX IF NOT EXISTS idx_unified_findings_class ON unified_findings(class_name);
CREATE INDEX IF NOT EXISTS idx_source_sink_uf_id ON source_sink_pairs(uf_id);
CREATE INDEX IF NOT EXISTS idx_framework_name ON framework_fingerprints(framework);
CREATE INDEX IF NOT EXISTS idx_auth_class ON auth_config(class_name);
