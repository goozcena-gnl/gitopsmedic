from __future__ import annotations

import copy
import difflib
import json


def _pretty(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

def remediate(manifest: dict) -> dict:
    candidate = copy.deepcopy(manifest)
    spec = candidate.setdefault("spec", {})
    replicas = spec.get("replicas", 1)
    if not isinstance(replicas, int) or replicas < 2:
        spec["replicas"] = 2

    metadata = candidate.setdefault("metadata", {})
    annotations = metadata.get("annotations") or {}
    reviewed_image = annotations.get("gitops-medic.dev/safe-image")

    pod_spec = spec.setdefault("template", {}).setdefault("spec", {})
    pod_sc = pod_spec.setdefault("securityContext", {})
    pod_sc["runAsNonRoot"] = True

    for container in pod_spec.get("containers") or []:
        image = str(container.get("image", ""))
        if reviewed_image and (image.endswith(":latest") or ":" not in image):
            container["image"] = reviewed_image
        resources = container.setdefault("resources", {})
        resources.setdefault("requests", {"cpu": "100m", "memory": "64Mi"})
        resources.setdefault("limits", {"cpu": "500m", "memory": "256Mi"})
        sc = container.setdefault("securityContext", {})
        sc["allowPrivilegeEscalation"] = False
        sc["readOnlyRootFilesystem"] = True
        sc.setdefault("capabilities", {"drop": ["ALL"]})
    return candidate

def unified_diff(original: dict, candidate: dict, target: str) -> str:
    return "".join(difflib.unified_diff(
        _pretty(original).splitlines(keepends=True),
        _pretty(candidate).splitlines(keepends=True),
        fromfile=target,
        tofile=target + ".candidate",
    ))
