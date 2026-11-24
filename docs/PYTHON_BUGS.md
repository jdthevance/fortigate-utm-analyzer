# Suspected Python behavior to revisit after the Go port

The Go port copies the Python behavior exactly, including anything listed
here. Each entry is fixed later, in its own change, with a test that shows the
intended behavior.

| Area | What Python does | Why it may be wrong | Found in |
| --- | --- | --- | --- |
| Certificates | Expiry findings compare `not-after` with the machine's current date (`date.today()`). | The same config gives different findings on different days, so results are not reproducible. The Go version should take the assessment date as an input. | Baseline setup |
