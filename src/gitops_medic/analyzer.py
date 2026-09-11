from __future__ import annotations

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
    pod_sc = pod_spec.get("securityContext") or {}
    if pod_sc.get("runAsNonRoot") is not True:
        findings.append(Finding("pod-run-as-non-root", "HIGH", "Pod is not required to run as non-root.", "spec.template.spec.securityContext.runAsNonRoot", "Set runAsNonRoot=true."))

    containers = pod_spec.get("containers") or []
    for i, container in enumerate(containers):
        prefix = f"spec.template.spec.containers[{i}]"
        image = str(container.get("image", ""))
        if image.endswith(":latest") or ":" not in image:
            findings.append(Finding("image-not-pinned", "HIGH", f"Container image is not pinned to an explicit non-latest version: {image or '<missing>'}.", f"{prefix}.image", "Replace it with the reviewed image stored in metadata annotation gitops-medic.dev/safe-image."))
        resources = container.get("resources") or {}
        if not resources.get("requests") or not resources.get("limits"):
            findings.append(Finding("resources-required", "MEDIUM", "Container does not define both resource requests and limits.", f"{prefix}.resources", "Add explicit CPU and memory requests/limits."))
        sc = container.get("securityContext") or {}
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(Finding("no-privilege-escalation", "HIGH", "Container may allow privilege escalation.", f"{prefix}.securityContext.allowPrivilegeEscalation", "Set allowPrivilegeEscalation=false."))
        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(Finding("readonly-rootfs", "MEDIUM", "Container root filesystem is writable.", f"{prefix}.securityContext.readOnlyRootFilesystem", "Set readOnlyRootFilesystem=true when workload permits."))
    return findings
