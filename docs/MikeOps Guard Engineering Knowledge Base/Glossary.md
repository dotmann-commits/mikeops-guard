# Glossary

- **Finding**: one issue with severity, location and fix.
- **Fingerprint**: stable 16-character hash of a finding, used in `ignore`.
- **failOn**: lowest severity that makes the run fail with exit 1.
- **Pwn request**: a `pull_request_target` workflow that checks out and runs fork code with secrets.
- **Script injection**: `${{ }}` expressions with attacker-controlled text expanded inside `run:` scripts.
- **SHA pinning**: referencing an action by full commit SHA instead of a movable tag.
- **SCA**: software composition analysis, finding vulnerable dependencies.
- **IaC**: infrastructure as code, such as Terraform, Kubernetes and Helm.
- **CVSS**: Common Vulnerability Scoring System, 0 to 10.
- **Bottle**: a prebuilt Homebrew package. Without one, Homebrew compiles from source.
