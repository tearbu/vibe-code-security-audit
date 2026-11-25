# Hardened sample: the same register, rebuilt

This is the same GRC register as the insecure sample next door, with
each of its problems fixed in the way the scanner's report recommends:

- Secrets come from environment variables. The app refuses to start
  if the session secret is not set, instead of falling back to a value
  written in the code.
- Every SQL query is parameterized.
- Every route except the login page sits behind a login check, and
  passwords are verified against a stored hash.
- Sign-ins, views, changes, and deletions go to an audit log with the
  acting user.
- CORS allows one named origin instead of any origin.
- Debug mode is off and the development server binds to localhost.
- Dependencies are pinned to exact versions.

The data is fictional. This is still a teaching sample, not a
product: a real deployment would add TLS, a production web server,
stronger session settings, and a review against the checklist in
`docs/assessment-checklist.md`.
