# Assessment checklist: reviewing an AI-built application by hand

The scanner in this project catches patterns in code. It cannot tell
me where the data flows, who signed off on the risk, or whether anyone
would notice a breach. Those are the questions that decide whether a
quickly built tool is safe to run, so I work through this checklist by
hand for any application that came out of an AI coding tool and is
about to hold real data.

I wrote it after reading a warning from a GRC practitioner about
vibe-coded GRC systems, and the framing is his point: a GRC system
holds the map of everything that is wrong in an organization, every
open vulnerability, every weak control, every accepted risk and who
owns it. In the wrong hands that is a menu for attacking the company.
The same caution applies to any tool built fast and holding sensitive
records, but GRC data is where the cost of getting it wrong is
highest.

## 1. Know what the system holds

- [ ] I can list the data the application stores, in plain language.
- [ ] I know which of it is sensitive: credentials, personal data,
      vulnerability details, risk acceptances, audit evidence.
- [ ] I know the classification the organization gives that data, and
      whether a tool like this is approved to hold it at all.
- [ ] Sample and test data in the project is fictional, and no real
      records were pasted into a chat or a prompt to build it.

## 2. Architecture and data flow

- [ ] I can draw, on one page, what talks to what: users, the app,
      the database, every external service.
- [ ] Every arrow on that drawing is one I intended. There are no
      mystery calls to analytics, error reporting, or AI endpoints
      that the generator added on its own.
- [ ] I know where the application runs and who else can reach it:
      public internet, office network, or one machine.
- [ ] The database is not reachable from anywhere except the app.

## 3. Where data is stored and sent

This is the control question. Generated code tends to spread data
around quietly.

- [ ] I know every place data rests: database, files, caches, logs,
      backups, and the AI tool's own history.
- [ ] I know what the AI coding tool itself received while the app
      was built: prompts, pasted code, sample records, error dumps.
- [ ] I have read the AI tool's terms for whether inputs are kept,
      reviewed by people, or used for training, and the answer is
      acceptable for this data.
- [ ] Secrets live in environment variables or a secrets manager,
      never in source, and anything that ever touched source has
      been rotated.
- [ ] Data leaving the app (emails, webhooks, exports) goes only to
      destinations I chose.

## 4. Access control design

- [ ] Every route that shows or changes data requires a signed-in
      user, and I tested that signed out, not just read the code.
- [ ] Users can only see their own scope of records. I tested with a
      second account, because generated code often checks that you
      are signed in and forgets to check that the record is yours.
- [ ] There is a separate admin role, and ordinary users cannot reach
      admin functions by guessing a URL.
- [ ] Passwords are hashed with a real password hashing function,
      sessions expire, and there is a way to force a sign-out.
- [ ] Default accounts and default passwords from the generated code
      are gone.

## 5. Secure development checks the scanner cannot do

- [ ] I read every file the tool generated, including the ones I did
      not ask about. Nothing in the project is a mystery to me.
- [ ] Dependencies are few, named, pinned, and from the real package
      index. A generated requirements file can invent package names,
      and an attacker can register the invented name first.
- [ ] Error pages and API errors do not return stack traces, SQL, or
      internal paths.
- [ ] File uploads, if any, are checked for type and size and stored
      where they cannot be executed.
- [ ] The code has no leftover test endpoints, debug routes, or
      commented-out back doors.

## 6. Monitoring and logging

- [ ] Sign-ins, failed sign-ins, record views, changes, and deletions
      are logged with the acting user and a timestamp.
- [ ] Logs do not themselves contain passwords, tokens, or full
      sensitive records.
- [ ] Someone actually reads the logs, or they feed a system that
      alerts. A log nobody opens is a diary, not a control.
- [ ] I would find out within a day if this application were being
      scraped or probed. If the honest answer is no, that is a
      finding, not a footnote.

## 7. Incident response readiness

- [ ] I know how to take the application offline in under five
      minutes.
- [ ] I know how to revoke every credential the app holds, and in
      what order.
- [ ] Backups exist, and I have restored one at least once to prove
      it works.
- [ ] I know who I would call and what I would say if the data in
      this system appeared somewhere it should not.

## 8. Leadership sign-off

- [ ] A named person with the authority to accept risk has seen the
      answers above and accepted the remaining risk in writing.
- [ ] The sign-off names what the system holds. Signing off on "an
      internal tool" is not the same as signing off on a map of every
      open vulnerability in the company.
- [ ] There is a review date. Tools built in an afternoon have a way
      of still running, unreviewed, two years later.

## How I use this with the scanner

I run the scanner first and fix what it finds. Then I work through
this checklist with the application open in front of me. Anything I
cannot answer becomes a finding with an owner and a date, the same
way I would record it in a real GRC register. The scanner takes
minutes. This list takes an hour or two. Both are cheaper than
explaining a leak.
