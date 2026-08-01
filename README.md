# {{APP_NAME}} — a governed emseapea app

This repository was created from your organization's approved template by the
emseapea provisioning broker. It comes with:

- CI that runs the SAME checks the deploy gate enforces (gitleaks + Semgrep) —
  green here means green at the gate. Semgrep checks the code against a set of
  known insecure patterns; it is not exhaustive and a green check is not a
  guarantee the code is secure — write safe code regardless of what the scan
  finds.
- A credential handle (never a raw secret) delivered via `get_workspace`;
  redeem it through your organization's gateway (`/u/<system>/...`).

Build whatever the approved intent describes. Every deploy goes through the
emseapea deploy gate.
