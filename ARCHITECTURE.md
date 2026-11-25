# Architecture

## What the project has

Three parts, on purpose:

1. `src/audit.py`: the scanner. One file, standard library only.
2. `samples/`: two small Flask-style GRC register apps with fictional
   data. One is deliberately insecure, one is the same register
   hardened. They are the scanner's proof cases.
3. `docs/assessment-checklist.md`: the human review that the scanner
   cannot automate.

## How a scan runs

The scanner walks the target directory and reads every `.py` file as
text, plus `requirements.txt` if one exists. It never imports or runs
the code it scans, which matters when the whole point is reviewing
code I do not trust yet.

Each check is a small function that takes a file path and its lines
and returns findings. A finding carries a severity (critical, high,
medium, low), a category, a file and line, a plain-language
explanation of why the pattern is a problem, and a remediation. Two
checks work at project level instead of file level: whether any
logging exists anywhere, and whether dependencies are pinned.

The route authentication check is the one heuristic in the set. It
finds route decorators, looks at the handler and the lines around it,
and reports the route if none of the usual signs of an auth check are
there. The finding is labeled as a heuristic in the output because
middleware outside the file could still protect the route, and only a
human (or a live test) can settle it.

Results are sorted by severity, then file, then line, and printed to
the console. With `--report` the scanner also writes a Markdown
report, and with `--json` a JSON file for tooling. The process exits
with code 1 when any critical or high finding exists, so the scan can
gate a build script.

## Why one file

I kept the scanner in a single file with no dependencies so anyone
can read all of it in one sitting and drop it into a project without
an install step. An audit tool I cannot read end to end is asking for
the same blind trust this project exists to question.

## Extending it

A new check is a function with the same shape as the existing ones,
added to the `FILE_CHECKS` tuple, plus a pair of tests: one fixture
that should be flagged and one that should not. The samples give a
third layer of protection, because a check that starts flagging the
hardened sample, or stops flagging the insecure one, fails the test
suite.
