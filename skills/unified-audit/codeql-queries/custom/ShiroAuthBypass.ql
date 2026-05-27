/**
 * @name Shiro Authentication Bypass via Path Traversal
 * @description Detects Shiro filter chain configurations that may be vulnerable to
 *              authentication bypass through path traversal (e.g., /admin/../public).
 *              CVE-2020-1957, CVE-2020-11989, CVE-2021-41303 etc.
 * @kind problem
 * @id java/shiro-auth-bypass
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-287
 */

import java

/** String constants that look like Shiro filter chain definitions */
class ShiroFilterChain extends StringLiteral {
  ShiroFilterChain() {
    // Matches patterns like "authc", "anon", "perms", "roles" in filter chains
    this.getValue().regexpMatch(".*(authc|anon|perms|roles|user|logout).*")
    and
    // Found in properties/yaml config context or Java code
    this.getCompilationUnit().getFile().getExtension() = ["java", "properties", "yml", "yaml"]
  }
}

/** Check for authc filter applied to path without proper ordering */
from ShiroFilterChain chain, string value
where
  value = chain.getValue() and
  // anon filter before authc on sensitive paths
  (
    value.regexpMatch(".*/admin.*=.*anon.*") or
    value.regexpMatch(".*/api.*=.*anon.*") or
    value.regexpMatch(".*/manage.*=.*anon.*")
  )
select chain,
  "Shiro filter chain may allow unauthenticated access to sensitive path: " + value
