# Triage a failed Guard run

| Exit | Meaning | Action |
|---|---|---|
| 1 | Findings at or above `failOn` | Open the HTML report artifact. Fix, or add a reasoned `ignore` entry. Rotate any secret first, then clean history. |
| 2 | Bad flag or config | The message names the config key. Run `mikeops-guard --help`. |
| 3 | Scanner crashed or is missing | `mikeops-guard doctor`. The report's scanner table shows the stderr tail. Trivy DB download failures are usually network related, so rerun. |
