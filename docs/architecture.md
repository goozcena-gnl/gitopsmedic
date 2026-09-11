# Architecture

## Principle

`READ -> PLAN -> VALIDATE -> HUMAN APPROVAL -> APPLY`

The LLM is deliberately outside the authorization path. It can explain normalized findings but cannot create shell commands, change severity, decide whether a proposal is safe, or write files. This makes the system closer to an auditable CloudOps control loop than a generic chatbot.

## Trust boundaries

1. Repository content: untrusted.
2. Scanner output: trusted only because rules are deterministic code.
3. LLM explanation: advisory/untrusted.
4. Candidate: untrusted until gates pass.
5. Proposal: valid only for one source SHA.
6. Apply: requires exact human token and apply-time revalidation.
