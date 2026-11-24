# Instructions for coding agents

Goal: port `utm.py` to Go with identical behavior. The Python tool is the
reference. The plan and status live in `docs/GO_PORT.md`.

## Rules

- Go code uses the standard library only. Ask before adding any dependency.
- Do not change behavior while porting. If the Python code looks wrong, add an
  entry to `docs/PYTHON_BUGS.md` and match Python anyway.
- Never commit real configurations, credentials or customer data. Test inputs
  go in `testdata/fixtures/` and must be sanitized first.
- Do not edit `testdata/golden/` by hand. Re-record it only after an
  intentional change to `utm.py`: `python3 scripts/compare.py --update-golden`.
- Work only on the task you were given. Do not create folders or packages it
  does not need.

## Done means

- `python3 -m unittest discover -s tests` passes.
- Once Go code exists: `gofmt -l .` prints nothing, and `go vet ./...` and
  `go test ./...` pass.
- `python3 scripts/compare.py --case <the cases you touched>` reports every
  case as `ok`.
- Your summary lists the files changed, the commands you ran and their results.
