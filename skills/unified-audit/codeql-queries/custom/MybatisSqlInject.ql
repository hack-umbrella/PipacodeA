/**
 * @name MyBatis SQL Injection via ${} interpolation
 * @description Detects MyBatis mapper XML or annotations using ${} string interpolation
 *              instead of #{} parameterized queries, which allows SQL injection.
 * @kind problem
 * @id java/mybatis-sql-injection
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 */

import java

/** MyBatis annotations that contain SQL */
class MybatisSqlAnnotation extends Annotation {
  MybatisSqlAnnotation() {
    this.getType().hasName(["Select", "Insert", "Update", "Delete",
                            "SelectProvider", "InsertProvider",
                            "UpdateProvider", "DeleteProvider"])
  }

  string getSqlValue() {
    result = this.getAValue().(CompileTimeConstantExpr).getStringValue()
  }

  predicate hasUnsafeInterpolation() {
    // Matches ${...} patterns in the SQL string
    this.getSqlValue().regexpMatch(".*\\$\\{[^}]+\\}.*")
  }
}

from MybatisSqlAnnotation anno, string sql
where
  sql = anno.getSqlValue() and
  anno.hasUnsafeInterpolation()
select anno,
  "MyBatis SQL annotation uses ${...} interpolation instead of #{...}, risking SQL injection: " + sql
