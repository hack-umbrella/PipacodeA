/**
 * @name Spring Expression Language (SpEL) Injection
 * @description Detects user-controlled input flowing into SpEL expression evaluation,
 *              which can lead to Remote Code Execution.
 * @kind path-problem
 * @id java/spel-injection-custom
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

/** SpEL expression evaluation sinks */
class SpelSink extends DataFlow::Node {
  SpelSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
      ma.getMethod().hasName("parseExpression") and
      this.asExpr() = ma.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasName("ExpressionParser") and
      ma.getMethod().hasName("parseExpression") and
      this.asExpr() = ma.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasName("StandardBeanExpressionResolver") and
      ma.getMethod().hasName("evaluate") and
      this.asExpr() = ma.getAnArgument()
    )
  }
}

/** Spring MVC request parameters as taint sources */
class SpringRequestParam extends DataFlow::Node {
  SpringRequestParam() {
    exists(Parameter p |
      this.asParameter() = p and
      p.getAnAnnotation().getType().hasName([
        "RequestParam", "PathVariable", "RequestHeader",
        "CookieValue", "RequestBody"
      ])
    )
  }
}

/** HttpServletRequest.getParameter as taint source */
class ServletParamSource extends DataFlow::Node {
  ServletParamSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["getParameter", "getHeader", "getAttribute"]) and
      ma.getMethod().getDeclaringType().hasName("HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

/** Combined taint source */
class SpelTaintSource extends DataFlow::Node {
  SpelTaintSource() {
    this instanceof SpringRequestParam or
    this instanceof ServletParamSource
  }
}

/** Taint propagation through string concatenation */
class SpelTaintConfig extends TaintTracking::Configuration {
  SpelTaintConfig() { this = "SpelTaintConfig" }

  override predicate isSource(DataFlow::Node src) {
    src instanceof SpelTaintSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SpelSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Integer.parseInt breaks taint
    exists(MethodAccess ma |
      ma.getMethod().hasName("parseInt") and
      ma.getMethod().getDeclaringType().hasName("Integer") and
      node.asExpr() = ma
    )
  }
}

from SpelTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SpEL expression depends on user-controlled $@, risking RCE",
  source.getNode(), "request parameter"
