/**
 * @name Fastjson Deserialization RCE
 * @description Detects Fastjson usage with autoType enabled or known dangerous classes,
 *              which can lead to Remote Code Execution via deserialization.
 * @kind problem
 * @id java/fastjson-deserialization
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-502
 */

import java

/** Fastjson parse/parseObject calls */
class FastjsonParseCall extends MethodAccess {
  FastjsonParseCall() {
    this.getMethod().getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSON") and
    this.getMethod().hasName(["parse", "parseObject", "parseArray"])
  }

  /** Check if input comes from untrusted source (not a string literal) */
  predicate hasDynamicInput() {
    not this.getAnArgument() instanceof StringLiteral
  }
}

/** ParserConfig.setAutoType(true) calls */
class AutoTypeEnabled extends MethodAccess {
  AutoTypeEnabled() {
    this.getMethod().getDeclaringType().hasQualifiedName("com.alibaba.fastjson.parser", "ParserConfig") and
    this.getMethod().hasName("setAutoType")
    and
    this.getAnArgument().(CompileTimeConstantExpr).getBooleanValue() = true
  }
}

/** Feature.SupportAutoType usage */
class AutoTypeFeature extends Expr {
  AutoTypeFeature() {
    this.(FieldAccess).getField().hasName("SupportAutoType")
    or
    this.toString().matches("%SupportAutoType%")
  }
}

from FastjsonParseCall call
where
  call.hasDynamicInput()
  and
  (
    // AutoType is globally enabled in the same compilation unit
    exists(AutoTypeEnabled ate | ate.getCompilationUnit() = call.getCompilationUnit())
    or
    // Feature.SupportAutoType is passed as argument
    exists(Expr arg | arg = call.getAnArgument() | arg instanceof AutoTypeFeature)
  )
select call,
  "Fastjson deserialization with autoType enabled on untrusted input — high RCE risk"
