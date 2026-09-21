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

deny contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.hostNetwork == true
  msg := "Pod must not enable hostNetwork"
}

deny contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.hostPID == true
  msg := "Pod must not enable hostPID"
}

deny contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.hostIPC == true
  msg := "Pod must not enable hostIPC"
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  input.spec.template.spec.volumes[i].hostPath
  msg := "Pod must not mount hostPath volumes"
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.containers[i]
  c.securityContext.privileged == true
  msg := sprintf("container %v must not be privileged", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.containers[i]
  c.securityContext.capabilities.add[_]
  msg := sprintf("container %v must not add Linux capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.initContainers[i]
  c.securityContext.privileged == true
  msg := sprintf("initContainer %v must not be privileged", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.initContainers[i]
  c.securityContext.capabilities.add[_]
  msg := sprintf("initContainer %v must not add Linux capabilities", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.ephemeralContainers[i]
  c.securityContext.privileged == true
  msg := sprintf("ephemeralContainer %v must not be privileged", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  some i
  c := input.spec.template.spec.ephemeralContainers[i]
  c.securityContext.capabilities.add[_]
  msg := sprintf("ephemeralContainer %v must not add Linux capabilities", [c.name])
}
