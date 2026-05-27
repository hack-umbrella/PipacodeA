/**
 * @name Spring Boot Actuator Endpoints Exposed
 * @description Detects Spring Boot Actuator endpoints that may be exposed without
 *              authentication, leaking sensitive information or allowing dangerous operations.
 * @kind problem
 * @id java/spring-actuator-exposed
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-200
 */

import java

/** Actuator endpoint mappings */
class ActuatorMapping extends Annotation {
  ActuatorMapping() {
    this.getType().hasName(["GetMapping", "PostMapping", "RequestMapping"]) and
    exists(Expr val | val = this.getAValue() |
      val.(CompileTimeConstantExpr).getStringValue().matches("%actuator%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%env%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%health%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%info%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%beans%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%configprops%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%mappings%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%metrics%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%trace%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%heapdump%") or
      val.(CompileTimeConstantExpr).getStringValue().matches("%threaddump%")
    )
  }
}

/** Check if the controller has auth annotations */
class ControllerWithAuth extends Class {
  ControllerWithAuth() {
    this.getAnAnnotation().getType().hasName(["RestController", "Controller"])
  }

  predicate hasAuthAnnotation() {
    exists(Annotation a | a = this.getAnAnnotation() |
      a.getType().hasName(["PreAuthorize", "Secured", "RolesAllowed"])
    )
  }
}

from ActuatorMapping anno, ControllerWithAuth ctrl
where
  anno.getCompilationUnit() = ctrl.getCompilationUnit() and
  not ctrl.hasAuthAnnotation()
select anno,
  "Spring Actuator endpoint may be exposed without authentication"
