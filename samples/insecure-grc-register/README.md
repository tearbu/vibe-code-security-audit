# Intentionally insecure sample: do not deploy

I wrote this app on purpose to be the kind of GRC register that comes
out of a rushed AI coding session. It works, and it is wrong in most
of the ways that matter:

- The session secret, a database password, and an API token are
  hardcoded in `app.py`.
- SQL queries are built by concatenating strings, so the owner filter
  and the delete route can be injected.
- Every route is open. There is no login at all.
- Nothing is logged, so there is no record of who viewed or deleted a
  risk.
- Debug mode is on and the server binds to every network interface.
- CORS allows any origin.
- Dependencies in `requirements.txt` are unpinned.

The data is fictional and the app is not connected to anything real.
I keep it in the project as the scanner's proof case: it should light
up, and the hardened version next door should not. Do not run it on a
network anyone else can reach, and do not copy its patterns into
anything real.
