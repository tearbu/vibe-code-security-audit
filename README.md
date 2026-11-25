# Vibe-Code Security Audit

A small audit kit I built to review applications that come out of AI
coding tools: a static scanner that catches the failure modes I keep
seeing in generated code, two sample apps that prove the scanner
works, and a checklist for the review a scanner cannot do.

## Story

I read a post by a GRC practitioner, Svein Waage, asking a question I
have not been able to put down: have you vibe-coded a GRC system? His
point was simple. A GRC system stores the most sensitive map an
organization has: every open vulnerability, every security control,
every risk assessment, and who is responsible for each one. A threat
actor with access to that system has a menu for how to break into the
organization. He described recent incidents involving AI coding tools,
including a breach at one tool vendor and a leak where a defence
company's sensitive material ended up somewhere it should never have
been, and his conclusion was that if you build your own GRC system
without real expertise on the team, you lose control of where your
data ends up.

I use AI tools to build. That is exactly why the post landed. The
tools write code that works on the first run, and working is not the
same as safe. The generated app I would have shipped a year ago had a
secret in the source, queries glued together from user input, and no
login on half the routes, and none of that stopped it from running
perfectly in a demo.

So I built the review I would want run on my own generated code
before it touches real data. The scanner checks the code. The
checklist checks everything around the code: where the data flows,
what the AI tool itself received, whether anyone would notice a
breach, and whether a named leader signed off on the risk. That last
part is the post's real demand, and no scanner can do it for you.

## How

The kit has three parts:

- `src/audit.py` is the scanner. One file, Python standard library
  only, nothing to install. It reads source as text and never runs
  the code it scans.
- `samples/` holds two small GRC register apps with fictional data.
  One is deliberately insecure, written the way a rushed generated
  app comes out. The other is the same register hardened. They are
  the scanner's proof cases.
- `docs/assessment-checklist.md` is the human review: architecture
  and data flow, where data is stored and sent, access control
  design, monitoring, incident response readiness, AI tool data
  handling, and leadership sign-off.

The scanner checks for:

| Check | What it looks for |
| --- | --- |
| Hardcoded secrets | Passwords, API keys, tokens, and private keys written as literals in source |
| SQL injection | Queries built with string concatenation, f-strings, or percent formatting |
| Debug mode | Framework debug flags set to true |
| Missing authentication | Routes with no sign of an auth check near the handler (heuristic, labeled as one) |
| No audit logging | A project with no logging calls anywhere |
| Unpinned dependencies | Requirements entries with no exact version |
| CORS wildcard | Cross-origin access open to any origin |
| Network binding | A development server bound to every interface, flagged with context |

Run it against any Python web app:

```
python3 src/audit.py path/to/app
python3 src/audit.py path/to/app --report report.md --json report.json
```

Each finding comes with a severity, the file and line, a plain
language explanation of why the pattern is a problem, and how to fix
it. The scanner exits with code 1 when a critical or high finding
exists, so it can sit in a build script and block a release.

### Decisions

- **Standard library only.** I wanted anyone to be able to read the
  whole scanner in one sitting and run it without trusting an install
  step. An audit tool that asks for blind trust misses the point of
  this project.
- **Heuristics are labeled as heuristics.** The route check cannot
  see middleware in another file, so its findings say so in the
  output instead of pretending to be certain. A finding that admits
  its limits gets fixed; a finding that cries wolf gets ignored.
- **Two sample apps instead of screenshots of output.** Anyone can
  run the scanner on the insecure sample and watch it light up, then
  run it on the hardened one and watch it come back quiet. Proof I
  can re-run beats proof I describe.
- **The checklist is a document, not code.** Data flow, vendor terms,
  and risk sign-off are judgment calls. Writing them as checkboxes
  with pointed questions keeps them human work instead of burying
  them in a tool that would only pretend to check them.

## Output

I ran the scanner against both sample apps. The full captured output
is in [docs/sample-scan-results.md](docs/sample-scan-results.md).

The insecure register produced **18 findings: 7 high, 7 medium, 4
low**, and the scanner exited with code 1. The findings cover every
category in the table above: three hardcoded secrets, three SQL
injection sites, debug mode on, five routes with no authentication,
no logging anywhere in the project, a CORS wildcard, a 0.0.0.0
binding, and three unpinned dependencies.

The hardened register produced **no findings** and exited with code
0. Same register, same features, with the fixes the report recommends
applied: secrets from the environment, parameterized queries, a login
check on every route, audit logging, a named CORS origin, pinned
versions.

The test suite has 21 tests and all of them pass. Each scanner check
is tested against code that should be flagged and the fixed version
of the same code, and two tests scan the sample apps themselves, so a
scanner change that stops telling the samples apart fails the suite.

```
python3 -m unittest discover -s tests
```

## Worth

If you build with AI tools, and most people shipping internal tools
now do, this kit is the pause between "it works" and "it holds real
data." The scan takes under a minute. The checklist takes an hour or
two. Both are cheaper than explaining to leadership how a map of
every open vulnerability in the company ended up readable by anyone
with the URL.

For reviewers and hiring managers: this project shows how I think
about the risk in AI-assisted development from the defender's side. I
build with these tools myself, I know where the bodies are buried
because I have buried some of them, and I would rather publish the
review kit than pretend the problem belongs to other people.

## Limitations

I want to be plain about what this kit does not do.

- The scanner reads patterns in text. It does not understand the
  program, so it will miss vulnerabilities that need real analysis,
  and it can flag code that is safe for reasons outside the file it
  is reading. Comments and strings are read as code, which cuts both
  ways.
- The route authentication check is a heuristic. Middleware, a
  reverse proxy, or a decorator defined in another file can all make
  a flagged route safe, or hide a missing check from the scanner.
- The scanner only reads Python files and `requirements.txt`. The
  ideas travel to other stacks; the code does not, yet.
- A clean scan is not a secure application. It means the specific
  mistakes in the check list were not found. The checklist exists
  because the dangerous questions, where the data goes, who can reach
  the system, who signed off, are not in the code at all.
- A scanner is not a substitute for expert review. That is the whole
  argument of the post that started this project, and building a
  small scanner has made me more sure of it, not less.

## Layout

```
src/audit.py                          the scanner
tests/test_audit.py                   21 tests, all passing
samples/insecure-grc-register/        deliberately insecure sample, do not deploy
samples/hardened-grc-register/        the same register, hardened
docs/assessment-checklist.md          the human review checklist
docs/sample-scan-results.md           captured scans of both samples
ARCHITECTURE.md                       how the scanner is put together
```

## License

MIT. See [LICENSE](LICENSE).
