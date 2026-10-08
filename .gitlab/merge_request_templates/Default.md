## What and why

## Checklist

- [ ] Names the guarantee it touches (the control plane's `docs/security.md`), or says none
- [ ] The hand-written part of `chart/README.md` describes the behaviour
- [ ] `tests/chart/regenerate.sh` run: the parameter table, the schema and the goldens are current, and the goldens' diff is what was intended
- [ ] A new behaviour has a render invariant that fails when it breaks
- [ ] Commits are signed off (`git commit -s`)
