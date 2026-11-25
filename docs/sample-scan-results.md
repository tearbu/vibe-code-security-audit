# Sample scan results

I ran the scanner in this project against the two sample apps that
ship with it. The output below is the real output of those runs,
captured on my machine, not edited to look better. The commands were:

```
python3 src/audit.py samples/insecure-grc-register
python3 src/audit.py samples/hardened-grc-register
```

The insecure app produced 18 findings and the scanner exited with
code 1, which is how I wired it: any critical or high finding fails
the run, so the scanner can sit in a build script and block a release.
The hardened app produced no findings and exited with code 0.

No findings on the hardened app means none of the patterns this
scanner knows about were present. It does not mean the hardened app
is secure. It means the specific mistakes the insecure app makes were
fixed, and a human review would still need to check the things on the
assessment checklist.

## Insecure app: full output

```
Audit target: samples/insecure-grc-register
Files scanned for a set of known failure patterns; see the limitations in the project README.

[HIGH] hardcoded-secret
  Where: app.py:24
  What: A secret value is assigned as a literal in the source: SECRET_KEY. Anyone who can read the code, a backup, or a chat transcript the code was pasted into has the secret.
  Fix: Move the secret to an environment variable or a secrets manager, and rotate the exposed value.

[HIGH] hardcoded-secret
  Where: app.py:27
  What: A secret value is assigned as a literal in the source: DB_PASSWORD. Anyone who can read the code, a backup, or a chat transcript the code was pasted into has the secret.
  Fix: Move the secret to an environment variable or a secrets manager, and rotate the exposed value.

[HIGH] hardcoded-secret
  Where: app.py:30
  What: A secret value is assigned as a literal in the source: RISK_FEED_TOKEN. Anyone who can read the code, a backup, or a chat transcript the code was pasted into has the secret.
  Fix: Move the secret to an environment variable or a secrets manager, and rotate the exposed value.

[HIGH] sql-injection
  Where: app.py:55
  What: A SQL statement is assembled by concatenating strings, so user input can change the query.
  Fix: Use parameterized queries: pass the SQL with placeholders and the values as a separate parameter tuple, and let the database driver handle quoting.

[HIGH] sql-injection
  Where: app.py:66
  What: A SQL statement is assembled by concatenating strings, so user input can change the query.
  Fix: Use parameterized queries: pass the SQL with placeholders and the values as a separate parameter tuple, and let the database driver handle quoting.

[HIGH] sql-injection
  Where: app.py:75
  What: A SQL statement passed to execute() is built with string formatting or concatenation.
  Fix: Use parameterized queries: pass the SQL with placeholders and the values as a separate parameter tuple, and let the database driver handle quoting.

[HIGH] debug-mode
  Where: app.py:89
  What: Debug mode is enabled. Framework debug modes can expose an interactive debugger and stack traces to anyone who can reach the app.
  Fix: Turn debug off outside local development and drive it from an environment setting that defaults to off.

[MEDIUM] no-audit-logging
  Where: (project)
  What: No logging calls appear anywhere in the project. With no audit trail there is no record of who viewed or changed data, which matters most for the systems that hold sensitive records.
  Fix: Add structured logging for sign-ins, record views, changes and deletions, and make sure the logs go somewhere they are reviewed.

[MEDIUM] cors-wildcard
  Where: app.py:42
  What: CORS is configured to allow any origin (*). Any website a user visits can make cross-origin requests to this app.
  Fix: Restrict allowed origins to the specific sites that need access.

[MEDIUM] missing-authentication [heuristic]
  Where: app.py:46
  What: This route shows no authentication check in or near its handler. If middleware elsewhere does not protect it, anyone who can reach the app can use this route.
  Fix: Require authentication on the route itself (for example a login decorator) so the protection is visible where the route is defined, and verify by hand that the route rejects anonymous requests.

[MEDIUM] missing-authentication [heuristic]
  Where: app.py:51
  What: This route shows no authentication check in or near its handler. If middleware elsewhere does not protect it, anyone who can reach the app can use this route.
  Fix: Require authentication on the route itself (for example a login decorator) so the protection is visible where the route is defined, and verify by hand that the route rejects anonymous requests.

[MEDIUM] missing-authentication [heuristic]
  Where: app.py:61
  What: This route shows no authentication check in or near its handler. If middleware elsewhere does not protect it, anyone who can reach the app can use this route.
  Fix: Require authentication on the route itself (for example a login decorator) so the protection is visible where the route is defined, and verify by hand that the route rejects anonymous requests.

[MEDIUM] missing-authentication [heuristic]
  Where: app.py:72
  What: This route shows no authentication check in or near its handler. If middleware elsewhere does not protect it, anyone who can reach the app can use this route.
  Fix: Require authentication on the route itself (for example a login decorator) so the protection is visible where the route is defined, and verify by hand that the route rejects anonymous requests.

[MEDIUM] missing-authentication [heuristic]
  Where: app.py:81
  What: This route shows no authentication check in or near its handler. If middleware elsewhere does not protect it, anyone who can reach the app can use this route.
  Fix: Require authentication on the route itself (for example a login decorator) so the protection is visible where the route is defined, and verify by hand that the route rejects anonymous requests.

[LOW] network-binding
  Where: app.py:89
  What: The development server binds to 0.0.0.0, which exposes it on every network interface, not just this machine. That is sometimes intended behind a firewall or in a container, and risky when it is not.
  Fix: Bind to 127.0.0.1 for local development, and put a real web server in front for anything shared.

[LOW] unpinned-dependency
  Where: requirements.txt:1
  What: Dependency 'flask' is not pinned to an exact version. The next install can silently pull a different, possibly compromised or breaking, release.
  Fix: Pin every dependency to an exact version (name==x.y.z) and review changes when versions are bumped.

[LOW] unpinned-dependency
  Where: requirements.txt:2
  What: Dependency 'requests' is not pinned to an exact version. The next install can silently pull a different, possibly compromised or breaking, release.
  Fix: Pin every dependency to an exact version (name==x.y.z) and review changes when versions are bumped.

[LOW] unpinned-dependency
  Where: requirements.txt:3
  What: Dependency 'python-dotenv' is not pinned to an exact version. The next install can silently pull a different, possibly compromised or breaking, release.
  Fix: Pin every dependency to an exact version (name==x.y.z) and review changes when versions are bumped.

Summary: 18 findings (high: 7, medium: 7, low: 4)
```

## Hardened app: full output

```
Audit target: samples/hardened-grc-register
Files scanned for a set of known failure patterns; see the limitations in the project README.

No findings. That means none of the patterns this scanner knows about were found. It does not mean the application is secure.
```

## What the contrast shows

Every category the scanner checks fires on the insecure app at least
once: hardcoded secrets, SQL injection, debug mode, missing
authentication, no audit logging, a CORS wildcard, a network binding
worth questioning, and unpinned dependencies. The hardened app fixes
each one in the way the report recommends: secrets from the
environment, parameterized queries, an explicit login decorator on
each route, audit logging, a named CORS origin, localhost binding,
and pinned versions. That is the loop I wanted to prove: generate,
scan, fix, scan again.
