package main

deny contains msg if {
  input.kind == "Deployment"
  input.spec.replicas < 2
  msg := "Deployment must use at least two replicas"
}

deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Pod must require runAsNonRoot"
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.containers[i]
  endswith(c.image, ":latest")
  msg := sprintf("container %v uses :latest", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.containers[i]
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %v must disable privilege escalation", [c.name])
}
