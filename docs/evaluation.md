# Evaluation

The MVP uses code-based evaluations so it remains fully local and deterministic. `make eval` verifies:

- a healthy manifest produces no findings;
- the insecure fixture produces the expected rule set;
- a prompt-injection annotation does not alter diagnosis;
- a manifest without a reviewed replacement image cannot become `safe_to_apply`.

The portfolio edition can add DeepEval, already present in Devops-Tools, for model-output quality regression tests. The authorization path should still remain code-based.
