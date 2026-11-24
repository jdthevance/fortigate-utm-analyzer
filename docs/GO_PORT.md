# Go port plan

The Go version must behave exactly like `utm.py` before anything is improved.
"Exactly" is checked by `scripts/compare.py`, which runs both implementations
on every fixture and CLI case and diffs every output file.

## Baseline (recorded 2026-11-24)

- Reference: `utm.py` 4.1.0 at commit `17055a8`.
- 97 Python tests pass.
- `--all` on the sample reports **310 findings, score 876.5**
  (CRITICAL 21, HIGH 78, MEDIUM 114, INFO 97). The README's example output
  further down (312 findings) is out of date: its counts do not add up to
  876.5. The 310 figure is the baseline.
- Outputs are deterministic, except the HTML `generated_at` timestamp, which
  the comparison masks. Certificate expiry checks depend on today's date
  (see `docs/PYTHON_BUGS.md`); the sample has no expiry dates, so it is not
  affected yet.

## How the comparison works

- Fixtures: `testdata/fixtures/*.conf`, sanitized only.
- Cases: every domain flag on its own, the README combinations, the long
  option spellings, `--html` alone, and `--all --summary --html`. List them
  with `python3 scripts/compare.py --list`.
- For each case it compares the exit code, the console output and every file
  written, after replacing the output path and the HTML timestamp.
- `testdata/golden/` holds the recorded Python outputs, so a change in
  Python behavior is caught by `tests/test_compare.py`.

| Command | Use |
| --- | --- |
| `python3 scripts/compare.py` | Go vs a live Python run (main check) |
| `python3 scripts/compare.py --case vpn,sslvpn` | Only some cases |
| `python3 scripts/compare.py --reference golden --candidate python` | Has Python drifted from the baseline? |
| `python3 scripts/compare.py --update-golden` | Re-record after an intentional Python change |

Console messages on stderr (argparse usage errors) are not compared.

## Milestone 1 tasks

Each task is one pull request and is done when its comparison cases pass.

1. [x] Agent instructions, Python baseline and comparison script.
2. [ ] Add 8 to 10 sanitized fixtures: several FortiOS versions, one
   multi-VDOM, one HA pair (owner: project maintainer).
3. [ ] Go module and `cmd/forti-analyzer` with every CLI option, standard
   library `flag` only. Options may appear after the config file name, as
   argparse allows.
4. [ ] Port the parser, checked against a JSON dump of the Python parser.
5. [ ] Port audit domains one or two at a time, starting with `-s` and `-f`.
6. [ ] Port the TXT reports, `--summary` JSON and the risk score.
7. [ ] Port the HTML report, embedding the existing template with `go:embed`.
8. [ ] CI runs Go tests and the comparison, and builds Linux, macOS and
   Windows binaries.

The web platform, database and collector are out of scope until this
milestone ships.
