# devsecops-pipeline-lab

[![security-pipeline](https://github.com/gl1tchdust/devsecops-pipeline-lab/actions/workflows/pipeline.yml/badge.svg)](https://github.com/gl1tchdust/devsecops-pipeline-lab/actions/workflows/pipeline.yml)

A GitHub Actions pipeline that runs six security tools against two deliberately
vulnerable APIs, applies a release gate that fails the build on High or
Critical, and **measures its own custom rules against hand-labelled ground
truth** so the accuracy claims can be checked rather than believed.

The tool list is table stakes. The parts worth reading are the measured
accuracy of the custom authorization rules, the cases they get wrong and why,
and the argument about which findings should block a release.

## 60-second quickstart

```bash
git clone https://github.com/gl1tchdust/devsecops-pipeline-lab
cd devsecops-pipeline-lab
./run-local.sh
```

Fetches both targets, runs every tool you have installed, scores the rules, and
evaluates the gate. Missing tools are skipped with a notice, so it works with
only Semgrep installed. Docker is needed for the container scan and ZAP.

Just the parts that need nothing but Python:

```bash
pip install -r requirements-dev.txt
semgrep test semgrep/rules/python
semgrep test semgrep/rules/javascript
python -m pytest -q
bash target/fetch.sh
python benchmark/benchmark.py --target target/vampi \
  --labels benchmark/labels/vampi.yml --rules semgrep/rules/python
```

## Measured rule accuracy

Six custom rules covering three authorization bug classes in two languages,
scored against defects labelled by hand in `benchmark/labels/`:

| Target | Language | Labelled | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|---|
| [VAmPI](https://github.com/erev0s/VAmPI) `f16052dc` | Python / Flask | 7 | 5 | 1 | 2 | **0.833** | **0.714** |
| [DVNA](https://github.com/appsecco/dvna) `9ba473ad` | JS / Express | 3 | 3 | 5 | 0 | **0.375** | **1.000** |

Reproduce either row with the command in the quickstart. The label files carry
the standard used, a note per defect, and corroborating evidence (upstream's
own vulnerability comments where they exist). If you think a label is wrong,
the thing to argue with is checked in.

CI enforces these as floors, so a rule edit that loses accuracy fails the build
instead of shipping quietly.

### Why DVNA's precision is bad, and why that is the most useful number here

VAmPI has an ownership model: books belong to users, so "load by id without an
ownership constraint" is a meaningful question. DVNA's `Product` model has no
owner column at all (`models/product.js` is `id, code, name, description,
tags`). Products are global. Every handler that loads one by `req.query.id`
looks exactly like BOLA to a syntactic rule and is not BOLA, because there is
no owner to violate. Four of the five false positives are that.

The honest conclusion: **these rules assume a multi-tenant data model.** Point
them at a codebase without one and they generate noise at roughly two false
positives per true one. Before running them on a real repo, restrict them to
the models that actually have an owner. A ruleset that needs that kind of
per-project configuration is normal; one that pretends it doesn't is the
problem.

Recall is 1.000 on DVNA and 0.714 on VAmPI, which is the opposite of what the
precision figures suggest, and is the reason both numbers are published rather
than whichever one flatters the ruleset.

### The benchmark decides which rules are allowed to block

Aggregate precision hides which rule carries the noise, so the scorer breaks it
down per rule. That number then sets the rule's severity, which is what
determines whether the gate blocks on it:

| Rule | Target | TP | FP | Precision | Gate |
|---|---|---|---|---|---|
| `missing-object-authorization` | VAmPI | 2 | 0 | **1.000** | blocks |
| `bfla-missing-function-authorization` | VAmPI | 3 | 1 | **0.750** | blocks |
| `js-bfla-missing-function-authorization` | DVNA | 1 | 1 | **0.500** | logs |
| `js-bola-missing-object-authorization` | DVNA | 2 | 4 | **0.333** | logs |
| `mass-assignment-privileged-field` | none | - | - | unmeasured | logs |
| `js-mass-assignment-privileged-field` | none | - | - | unmeasured | logs |

**The policy: a rule blocks only when its measured precision on a benchmarked
target is at least 0.75. A rule nothing has measured does not block, however
good its fixtures look.**

So the two mass-assignment rules log rather than block, despite having the most
thorough fixtures in the repo, because no benchmark target exercises them:
VAmPI's instance is the documented control-flow miss and DVNA has none. And the
JavaScript rules log because being wrong two times in three is how a gate gets
routed around. Each rule's YAML carries the measurement that set its severity,
in a `Gate policy:` comment next to the number.

This is the part that makes the benchmark load-bearing rather than decorative.
Without it, "should this rule block the build?" is a matter of taste.

Recall is deliberately absent from the per-rule table. A label records that a
defect exists, not which rule ought to have caught it, so attributing a miss to
a particular rule would be an assumption rather than a measurement.

## The gate is supposed to fail

Running a High/Critical gate against deliberately vulnerable APIs and expecting
green would be incoherent. CI asserts the inverse: **the `gate` job passes when
`gate.py` blocks the release, and fails if the gate ever goes green.** A gate
that waves these targets through is a broken gate, and that is what turns the
build red.

The other direction, that the gate returns 0 on clean input, honours
suppressions and rejects expired ones, is covered by unit tests that run before
anything else in the pipeline. 50 tests across the gate and the scorer.

## What each tool catches that the others miss

Measured against VAmPI at `f16052dc`, not quoted from marketing pages.

| Tool | Sees | Found here | The gap it fills |
|---|---|---|---|
| Semgrep, registry rules | Source | 1 | Hardcoded `SECRET_KEY` at `config.py:13`. |
| Semgrep, custom rules | Source | 6 | Both BOLA sites and four BFLA sites, one of which is a false positive. Registry rules found none of them. |
| Trivy `fs` | Declared deps | 14, 1 Crit + 5 High | CVEs in `flask` 2.2.2 and `PyJWT` 2.6.0. Reads intent, not what shipped. |
| Trivy `image` | Built layers | 32, 1 Crit + 10 High | 18 findings the dependency scan never sees. |
| Trivy `config` | Dockerfile | 2 High, 1 Low | Runs as root, `apk add` without `--no-cache`, no `HEALTHCHECK`. |
| Gitleaks | Full git history | 0 | Secrets in commits no longer checked out. |
| Syft + Grype | SBOM of 13 components | 14 | A re-scannable artifact. As a second opinion it added nothing here, see below. |
| ZAP baseline | The running app | 4, all Low/Info | Response headers. Nothing else, see below. |

Three results are worth stopping on.

**The registry rulesets do not find authorization bugs.** Against VAmPI:

| Ruleset | Findings |
|---|---|
| `p/python` + `p/flask` | 0 |
| `p/owasp-top-ten` | 0 |
| `p/security-audit` | 1, the hardcoded secret |
| custom rules in this repo | 6 |

Not a knock on Semgrep. Authorization is application-specific by definition: no
vendor can know your tenancy column is called `user_id`. It is why the custom
rules exist, and why "we run Semgrep" is not the same sentence as "we test
authorization."

#### Someone else measured the same thing at larger scale

VAmPI is a teaching target, so a negative result on it is suggestive rather
than conclusive. ProjectDiscovery published a benchmark that is neither: three
full-stack applications built by AI coding tools with ordinary product
requirements, not prompted to be vulnerable, with 74 vulnerabilities confirmed
by hand and classified in a public
[`FINDINGS.csv`](https://github.com/projectdiscovery/research/tree/main/vibe-coding).

Scored against that ground truth, by their measurement, not mine:

| Scanner | Caught of 74 | False positives |
|---|---|---|
| Neo | 66 | 5 |
| Claude Code | 41 | 24 |
| Invicti (DAST) | 10 | 10 |
| **Snyk** | **0** | 5 |
| **Semgrep** | **0** | 3 |

Twenty-one of those 74 are authorization or access-control defects, including
one Critical and seven High. Semgrep's registry found none of them, and neither
did Snyk.

Two stages of *this* pipeline are Semgrep and Snyk. So the fair reading of this
repo is not "these six tools cover you." It is that the dependency and
secret-scanning stages do what they are good at, and the authorization coverage
comes entirely from rules someone wrote for the application in front of them.

Source: ProjectDiscovery,
["Inside the benchmark"](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught).
Their apps are not yet scored here: all three use ORMs these rules do not
recognise (Prisma, Drizzle, SQLAlchemy's expression API), so running them today
would measure the gap in my pattern coverage rather than anything about the
bug classes. Tracked as an issue.

**Gitleaks found nothing, and Semgrep found the secret.** `SECRET_KEY = 'random'`
is a real hardcoded credential. Gitleaks scanned the entire history and did not
flag it, which is correct behaviour: gitleaks matches credential shapes and
entropy, and `'random'` is a five-letter lowercase word. Semgrep caught it
because it knows the assignment target is a Flask secret. Two tools with
overlapping names and almost no overlapping coverage.

**Dependency scanning and image scanning are different scans.** `trivy fs`
reads `requirements.txt`, a statement of intent. `trivy image` reads what is
actually in the layers. Measured on this target the image scan is a strict
superset: 32 findings against 14, adding **18 the dependency scan never sees**
and missing none of them. A pinned `requirements.txt` says nothing about the
Alpine packages underneath it.

**Grype added nothing over Trivy, and cost the gate accuracy.** Both found
exactly 14 vulnerabilities in the same two packages with the same severity
split. Not one extra finding between them. But Trivy reports CVE identifiers
and Grype reports GHSA identifiers, and the overlap between the two sets is
*zero* by identifier:

```
trivy fs : CVE-2023-30861, CVE-2026-32597, CVE-2026-48526, ...
grype    : GHSA-68rp-wp8r-4726, GHSA-2gx3-rcp4-g85q, ...
```

Same vulnerabilities, different names. The gate keys suppressions on rule id,
so it counts them as 28 distinct findings and a suppression written for a CVE
will not silence its GHSA twin. Running both scanners buys nothing here and
would make every dependency exception need writing twice.

That is a limitation of the gate, not of either tool. The fix is an advisory
alias map (GHSA to CVE) before matching, which this repo does not implement. It
is a deliberate omission rather than an oversight: the honest version of "we
run two SCA tools for coverage" is that you need identifier normalisation
first, and most pipelines that stack scanners do not have it.

**A ZAP baseline scan does not test authorization.** It found 4 alerts, all Low
or Info: a missing `Cross-Origin-Resource-Policy` header, a leaked `Server`
version, a missing `X-Content-Type-Options`, and cacheable content. Zero High.
Against the same application where the static rules found seven authorization
defects, the baseline scan found **none of them**.

That is correct behaviour. `zap-baseline.py` is a passive spider and a header
check; it never authenticates as two different users, so it cannot possibly
observe that one of them can read the other's records. It is in the pipeline
because runtime headers are a real surface nothing else looks at, not because
it covers DAST. Testing authorization dynamically needs two sessions and a
differential comparison, which is a different tool and is out of scope here.

## The rules

Six rules, three bug classes, two languages. Each has fixture-based unit tests
run by `semgrep test`.

| Bug class | OWASP | CWE | Python | JavaScript |
|---|---|---|---|---|
| Object-level authz | API1:2023 | CWE-639 | `bola-missing-object-authorization` | `js-bola-missing-object-authorization` |
| Function-level authz | API5:2023 | CWE-862 | `bfla-missing-function-authorization` | `js-bfla-missing-function-authorization` |
| Mass assignment | API3:2023 | CWE-915 | `mass-assignment-privileged-field` | `js-mass-assignment-privileged-field` |

### BOLA: is the query scoped to the caller?

Three conditions, all required: the identifier is request-controlled, an ORM
load is keyed on it, and the same query is not narrowed by an ownership column
(`user`, `user_id`, `owner`, `owner_id`, `account_id`, `tenant_id`).

Authentication deliberately plays no part. Every handler the rule flags in
VAmPI had already validated a token. A token proves *who* is calling, never
*what* they may touch, and conflating the two is the whole bug class.

The two languages need different machinery. In Python the request-controlled
identifier is a bare handler parameter, because Flask and connexion pass path
parameters as named arguments. In Express it is syntactically explicit
(`req.body`, `req.query`, `req.params`), which makes the JS rule more precise
for free.

### BFLA: may you call this operation at all?

A privileged operation (bulk read, destructive write, role change) reached with
no authorization check in the handler and no auth decorator.

Confidence is marked LOW, deliberately. The set of names that count as an
authorization check is project configuration, not a universal constant, and in
Express the check usually lives in route-level middleware in a different file
that the rule never sees. Read the route table before acting on a finding.

This rule found the result worth showing in an interview: DVNA's
`/app/admin/usersapi` returns every user row including password hashes, mounted
with `isAuthenticated` and nothing else, while the `/app/admin` page it backs
renders conditionally on `req.user.role == 'admin'`. The page checks the role.
The JSON endpoint behind it does not.

### Mass assignment: can the caller pick the column?

Taint mode, both languages. Sources are the request body and query; sinks are
privilege-bearing fields and blind writes (`Model(**body)`, `Model.create(body)`,
`Object.assign(user, req.body)`, `setattr` loops over request keys).

Taint mode rather than pattern matching, because the version that gets caught
in review is `User(admin=request.json["admin"])` and the version that ships is
`body = request.get_json()` on line 3 and `User(**body)` on line 40.

## What the tuning actually cost and bought

Every number below is a measured before/after on the real targets, not an
estimate. These are the parts an interviewer can usefully push on.

**Ownership exclusions, Python BOLA: removed 1 false positive in 3.**
Stripping the six `pattern-not` clauses and re-running on VAmPI gives 3
findings instead of 2. The extra one is `books.py:63`, which sits twelve lines
below the true positive inside the `else` of the same branch:

```python
# books.py:51  flagged, correctly
book = Book.query.filter_by(book_title=str(book_title)).first()

# books.py:63  not flagged, also correctly
user = User.query.filter_by(username=resp['sub']).first()
book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
```

One keyword argument is the difference between the fix and the bug. That is why
a rule keyed on "is there an ownership constraint" beats one keyed on "is there
an auth check."

**Static-method guard: removed 3 false positives in 9.** Before it, both Python
rules fired inside `models/user_model.py`, because "a function with a
parameter" was standing in for "a route handler." A model helper has no
business enforcing authorization; its caller does. Flagging the data layer
moves the finding away from where the fix belongs. Excluding `@staticmethod`
and `@classmethod` is precise enough to keep class-based views working.

**`findAll` removed from the JS BOLA sinks.** BOLA is about addressing one
object. A list or search returning many rows is a filtering concern and belongs
to the BFLA rule. Including it cost precision on DVNA's product search for
nothing.

**Semgrep treats a literal `{}` in a pattern as a wildcard.** `findAll({})`
also matches `findAll({ where: ... })`, which silently turned the JS BFLA rule
from "unbounded read" into "any read" and produced two false positives.
`pattern-not` on the `where` shape is what makes the rule mean what it says.
Verified directly: a `{}` pattern matches both `a.findAll({})` and
`c.findAll({ where: { x: 1 } })`.

**Object-literal exclusion in JS mass assignment.** Taint propagates into a
fresh object literal built from tainted fields, so `create({ name: req.body.name })`
is tainted and was flagged, even though it is the fix. Excluding object-literal
arguments fixes that and costs the `create({ ...req.body })` spread case, which
is now a recorded miss.

## Known limitations

Recorded as annotated fixtures, so they are enforced as current behaviour
rather than described in prose and quietly drifting.

**Taint analysis cannot see VAmPI's actual mass assignment.** The real code is:

```python
if request_data['admin']:
    admin = True
else:
    admin = False
user = User(..., admin=admin)
```

The attacker controls the *branch*, not the *value*. `admin` holds a boolean
literal, so taint analysis is right that it carries no taint. Catching this
needs control-dependence (implicit flow), which Semgrep's taint engine does not
track and which is a general limit of taint analysis. This is one of VAmPI's
two false negatives.

**Custom accessors.** `users.py:46` is an unauthenticated read of any user
record via `User.get_user(username)`. The BOLA rule misses it because the load
does not go through `.query.filter_by`, and the BFLA rule misses it because
`get_user` is not a privileged-accessor name. VAmPI's other false negative.

**Ownership constraints built in a variable.** The JS rule needs the request
reference inside the call it matches, so a `where` clause assembled a line
earlier is skipped whether or not it is safely scoped. Costs recall, not
precision.

**Ownership column not on the list.** A codebase using `org`, `workspace_id` or
`customer_ref` needs those names added. Project configuration, not a universal
constant.

**Present but untrustworthy ownership values.** `filter_by(user_id=request.args['uid'], id=$ID)`
is still BOLA. The rule checks that an ownership constraint *exists*, not that
its value can be trusted.

**Pre-authentication handlers.** A forgot-password flow must look a user up by
the submitted login; there is no session yet to scope the query to. Two of
DVNA's five false positives are this.

**Route-level middleware is invisible.** The BFLA rule sees only the handler, so
an Express route properly guarded by `isAdmin` in the route table still reports.

**Non-ORM data access.** Raw SQL and HTTP calls to other services are out of
scope entirely.

A ruleset that finds eight real defects across two codebases and misses two is
worth shipping. One presented as complete coverage of a bug class is not.

## What blocks a release, what only gets logged

| Severity | Behaviour | Why |
|---|---|---|
| Critical, High | **Blocks.** | Exploitable, or one step from it. |
| Medium | Logged. | Real, but blocking on Medium trains people to bypass the gate, and a gate people bypass protects nothing. |
| Low, Info | Logged. | Missing `HEALTHCHECK` should not stop a deploy. |
| Any expired suppression | **Blocks.** | See below. |
| Unparseable report | **Blocks**, exit 2. | A truncated report and a clean scan both look like "no findings". They must never be treated alike. |
| Accuracy below floor | **Blocks.** | A rule edit that loses precision or recall is a regression. |

On the latest CI run that is 82 findings: 30 blocking, 2 suppressed, 50 logged.

Severity is normalised across tools so Trivy's CVSS 7.5 and a Semgrep `ERROR`
land in the same band. The order is: numeric `security-severity` if present,
then the result's own SARIF `level`, then the rule's
`defaultConfiguration.level`, then the spec default of `warning`.

### The bug that third step fixes

The gate originally read only `result.level`. Every Semgrep finding came out
MEDIUM and sailed through, including a hardcoded Flask `SECRET_KEY`.

Semgrep writes no `security-severity` and no `level` on results at all. It puts
the severity in the rule's `defaultConfiguration.level`, which is exactly what
SARIF 2.1.0 says to do: a result omits `level` when it matches the level its
rule already declares, and a consumer is expected to look there. Reading only
the result was a spec compliance bug on my side, not a Semgrep quirk.

Worth noting how it surfaced. Unit tests did not catch it, because the fixtures
were written against the same wrong assumption as the code. It showed up the
first time the gate ran on real Semgrep output and the authorization findings,
the entire point of the repo, were sitting in the logged pile. Four regression
tests now cover the precedence order.

ZAP does not emit SARIF at all and gets its own `riskcode` adapter.

Semgrep and Trivy dependency findings are also uploaded to GitHub Code
Scanning, so they appear in the Security tab with line annotations on the diff.

## Suppressions

All of them live in `gate/suppressions.yml`. One file, so exceptions are
reviewable in one diff instead of scattered across six tool configs.

The gate enforces rather than trusts:

- **A justification is mandatory.** No `reason`, no suppression, build fails.
- **An expiry is mandatory, and is checked.** Past its date the gate fails *on
  the suppression itself*. This is the part most suppression files get wrong: a
  dated exception nobody revisits is a permanent hole with extra paperwork.
  Breaking the build is the only thing that guarantees somebody looks again.
- **Scope is narrow by default.** `tool` and `path` narrow the match. Without
  them a rule id is silenced everywhere, including where it is a real finding.
  Two tests cover exactly that.

Currently suppressed: two Trivy Dockerfile findings on the *target* image
(`DS-0002` root user, `DS-0025` `apk` cache), because the target is a
third-party container that exists to be attacked inside CI and is never
published. Both expire 2026-12-06. Nothing in either target's application code
or dependencies is suppressed, which is why the gate still blocks.

## Layout

```
.github/workflows/pipeline.yml   9 jobs: self-test, benchmark, 6 scanners, gate
semgrep/rules/python/            3 rules + fixtures
semgrep/rules/javascript/        3 rules + fixtures
benchmark/benchmark.py           precision/recall scorer, per-rule breakdown
benchmark/summarise.py           renders the CI job summary table
benchmark/labels/                hand-labelled ground truth, with evidence
gate/gate.py                     report normalisation, suppressions, verdict
gate/suppressions.yml            every exception, with expiry
target/fetch.sh                  pins both scan targets
run-local.sh                     the one command
```

## Notes

- Targets are pinned to commits, not branches. A moving target makes results
  unreproducible: you cannot tell an improved rule from an upstream edit.
- Targets are fetched at build time, never vendored, so this repo carries no
  third-party source. Both are MIT licensed.
- The Snyk stage is optional. Without `SNYK_TOKEN` it emits a notice and skips,
  so a fork gets a clean green run instead of a confusing red one.
- Scanners never fail their own job on findings, only on tool error. Deciding
  what a finding means is the gate's job, and that decision lives in one place.

## License

MIT. See [LICENSE](LICENSE).

Shivam Mahajan, https://linkedin.com/in/shivam-mahajan-a8005a205
