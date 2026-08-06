# driftify

Companion tool to inspectah: applies synthetic drift to a fresh RHEL, CentOS Stream, or Fedora system so every inspectah inspector has something to detect.

## Orientation

Read `design.md` first: design principles, OS version handling, profiles, the coverage map (which drift maps to which inspectah inspector), and script structure. It's the source of truth for why driftify is built the way it is.

## Layout

`driftify.py` is a single file at the repo root, not a package tree. There is no `src/`. Profiles, OS-version branching, and all section builders live in that one file; see `design.md` § Script Structure for how it's organized internally.

## Testing

`make test` (`python3 -m unittest discover -s tests -v`) is the canonical entry point, covering `tests/test_driftify.py` and `tests/test_multi_fleet.py`.

`run-architect-test.sh` and `run-fleet-test.sh` are not unit tests. They're integration/demo runners that fetch `driftify.py` from GitHub and need sudo plus a real (throwaway) VM or the inspectah binary. Don't run them as a substitute for `make test`.

## Language status

`driftify.py` is Python and stays Python; that's a deliberate design choice (see `design.md` § Runtime Model), not a placeholder for a future rewrite. Don't propose porting it to Go or Rust. Active Go/Rust work in this ecosystem is on inspectah's side, not driftify's.

## Key Conventions

- **Commit format:** `type(scope): description` in imperative mood. Attribution: `Assisted-by: Claude Code (<model>)`. No team member names (this is a public repo).
- **Never push.** Commit freely; Mark pushes manually.
- **Changelog:** user-visible changes get a CHANGELOG.md entry under `[Unreleased]`, per `process-docs/changelog-policy.md`.
