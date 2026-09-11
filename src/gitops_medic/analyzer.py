from __future__ import annotations

from .images import is_image_pinned
from .models import Finding


def analyze(manifest: dict) -> list[Finding]:
    findings: list[Finding] = []
    if manifest.get("kind") != "Deployment":
        findings.append(Finding("unsupported-kind", "LOW", "MVP supports Kubernetes Deployment objects only.", "kind", "Use a Deployment fixture for the MVP."))
        return findings

    spec = manifest.get("spec", {})
    replicas = spec.get("replicas", 1)
    if not isinstance(replicas, int) or replicas < 2:
        findings.append(Finding("availability-replicas", "MEDIUM", "Deployment has fewer than two replicas.", "spec.replicas", "Use at least two replicas for the demo workload."))

    pod_spec = spec.get("template", {}).get("spec", {})
    for field, rule in (("hostNetwork", "host-network"), ("hostPID", "host-pid"), ("hostIPC", "host-ipc")):
        if pod_spec.get(field) is True:
            findings.append(Finding(rule, "HIGH", f"Pod enables {field}.", f"spec.template.spec.{field}", "Remove host namespace access after workload review."))
    for index, volume in enumerate(pod_spec.get("volumes") or []):
        if "hostPath" in volume:
            findings.append(Finding("host-path", "CRITICAL", "Pod mounts a host filesystem path.", f"spec.template.spec.volumes[{index}].hostPath", "Remove the hostPath volume after workload review."))
    pod_sc = pod_spec.get("securityContext") or {}
    if pod_sc.get("runAsNonRoot") is not True:
        findings.append(Finding("pod-run-as-non-root", "HIGH", "Pod is not required to run as non-root.", "spec.template.spec.securityContext.runAsNonRoot", "Set runAsNonRoot=true."))

    if not pod_spec.get("containers"):
        findings.append(Finding("containers-required", "HIGH", "Deployment has no regular containers.", "spec.template.spec.containers", "Provide a valid Deployment with at least one container."))
    containers = [(kind, index, container) for kind in ("containers", "initContainers", "ephemeralContainers") for index, container in enumerate(pod_spec.get(kind) or [])]
    for kind, index, container in containers:
        prefix = f"spec.template.spec.{kind}[{index}]"
        image = str(container.get("image", ""))
        if not is_image_pinned(image):
            findings.append(Finding("image-not-pinned", "HIGH", f"Container image is not pinned to an explicit non-latest version: {image or '<missing>'}.", f"{prefix}.image", "Supply a reviewed --replacement-image to PLAN; repository annotations are not trusted image inputs."))
        resources = container.get("resources") or {}
        if not resources.get("requests") or not resources.get("limits"):
            findings.append(Finding("resources-required", "MEDIUM", "Container does not define both resource requests and limits.", f"{prefix}.resources", "Add explicit CPU and memory requests/limits."))
        sc = container.get("securityContext") or {}
        if sc.get("privileged") is True:
            findings.append(Finding("privileged-container", "CRITICAL", "Container enables privileged execution.", f"{prefix}.securityContext.privileged", "Remove privileged execution after workload review."))
        if (sc.get("capabilities") or {}).get("add"):
            findings.append(Finding("added-capabilities", "HIGH", "Container adds Linux capabilities.", f"{prefix}.securityContext.capabilities.add", "Remove added capabilities after workload review."))
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(Finding("no-privilege-escalation", "HIGH", "Container may allow privilege escalation.", f"{prefix}.securityContext.allowPrivilegeEscalation", "Set allowPrivilegeEscalation=false."))
        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(Finding("readonly-rootfs", "MEDIUM", "Container root filesystem is writable.", f"{prefix}.securityContext.readOnlyRootFilesystem", "Set readOnlyRootFilesystem=true when workload permits."))
    return findings
