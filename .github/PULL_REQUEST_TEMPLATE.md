<!--
Thanks for contributing. CONTRIBUTING.md has the full checklist; this template
is the short version of it.
-->

## What changes for a user

<!--
Not what changed in the code -- what someone running CveDeck will notice. If the
answer is genuinely "nothing", say so; internal refactors are welcome, they just
belong under a different heading.
-->

## Why

<!--
The problem this solves. If it fixes an issue, link it: "Fixes #123".
-->

## Checklist

- [ ] `cd backend && pytest` passes
- [ ] `cd frontend && npm test && npm run typecheck` passes
- [ ] Tests added or updated for the behaviour this changes
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Spec updated (`.kiro/specs/cvedeck/`) if this changes intended behaviour
- [ ] `DEPLOYMENT.md` updated if this adds a config knob
- [ ] `AGENTS.md` §3 updated if this adds or changes an invariant
- [ ] Hooks enabled (`git config core.hooksPath .githooks`) and not bypassed
- [ ] No real hostname, address, or credential from your own network — **including
      in test fixtures and UI placeholders**, which is where one got through before

## Anything you are unsure about

<!--
Optional, and genuinely useful. A note saying "I could not work out where this
belonged" gets a faster review than silence.
-->
