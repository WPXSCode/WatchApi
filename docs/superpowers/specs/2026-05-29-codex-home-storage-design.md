# Codex Home Storage Design

## Context

WatchApi runs Codex with an isolated `CODEX_HOME` per config and agent. This
prevents concurrent configs from overwriting the real `~/.codex/config.toml` and
`auth.json` while WatchApi injects endpoint, model, sandbox, and approval
settings.

The current implementation also copies the real Codex `sessions`,
`archived_sessions`, and `state_5.sqlite` into each isolated home before launch.
On the inspected machine, the real Codex session history is about 5.47 GB, so
copying it per config multiplies disk usage by the number of configs.

## Goal

Reduce per-config isolated Codex Home disk usage while preserving the ability to
resume old Codex sessions.

## Non-Goals

- Do not remove config-level isolation for `config.toml` and `auth.json`.
- Do not disable session restore or force all configs to start new sessions.
- Do not rely on symlinks or hard links as the primary strategy because Windows
  permissions, portable packaging, cross-drive paths, and antivirus behavior can
  make them unreliable.

## Design

### Lightweight Isolated Home

`prepare_isolated_codex_home` should continue creating a stable isolated home per
config and agent. It should copy only lightweight state needed for launch:

- `config.toml`
- `auth.json`
- `.codex-global-state.json`
- `state_5.sqlite`, if Codex still needs it for current runtime behavior

It should not bulk-copy `sessions` or `archived_sessions` from the real Codex
Home.

### Resume Lookup From Source Home

The launch path should distinguish two Codex homes:

- Runtime home: the isolated home passed through `CODEX_HOME` and used by the
  Codex process.
- Source home: the real configured `codex_home`, used as the authoritative index
  for existing historical sessions.

When WatchApi tries to restore a session, `CodexSessionIndex` should search the
source home, not the lightweight isolated runtime home. Session binding behavior
should stay keyed by config, agent, driver, and workdir.

### On-Demand Session Copy

If WatchApi resumes a historical Codex session found in the source home, it
should copy only the selected session file into the matching relative path under
the isolated runtime home before starting Codex.

This keeps Codex able to read the resumed session under its isolated
`CODEX_HOME`, without copying unrelated historical session files.

### Merge Back

Stopping a Codex process should still merge session output back into the source
home. The merge should avoid treating pre-copied historical files as new bulk
history. The implementation should track or infer which session files were
created or modified during the isolated run and copy those files back to the
source home.

The isolated `config.toml` and `auth.json` remain private to the runtime home and
must not be copied back to the source home.

### Cleanup Existing Expanded Homes

After the code change, existing `Runtime/codex-homes/*/sessions` and
`Runtime/codex-homes/*/archived_sessions` directories are obsolete cached copies.
They can be removed by a cleanup action without deleting the real session
history in `~/.codex`.

## Error Handling

- If the selected historical session file cannot be copied, startup should fail
  with a clear error that names the source and target paths.
- If merge-back cannot copy a session file, WatchApi should keep the current
  best-effort behavior for stop-time cleanup and avoid corrupting the source
  home.
- Missing source session files should fall back to the existing missing-session
  policy: start a new session or use the configured legacy latest behavior.

## Testing

Focused unit tests should cover:

- Preparing an isolated home no longer bulk-copies `sessions` or
  `archived_sessions`.
- Restore lookup can find a historical session in the source home while the
  isolated home starts without historical sessions.
- Resuming a selected historical session copies only that session file into the
  isolated home.
- Merge-back copies the current run's new or modified session file to the source
  home without copying unrelated historical files.
- Existing `config.toml` and `auth.json` in the source home are not overwritten
  by isolated runtime edits.

## Open Decisions

No open product decisions remain. The approved behavior is to preserve old
session resume support while removing bulk historical session copies from each
isolated home.
