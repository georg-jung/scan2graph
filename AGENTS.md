# Working agreement

How the owner of this repository wants work done here. Read it before planning
anything; it overrides habit, not judgement.

## Size is a feature

* Fewer lines is better, always. Deleted code is the best code. A shorter
  version that is harder to follow is not a win.
* This is a **single-container appliance for one household or small office**.
  One printer, a handful of users. Not multi-tenant, no scale-out, no
  compliance regime. Do not defend against situations this deployment cannot
  produce, and do not generalize for a second user of the code.
* Every environment variable is a lifelong support burden. Default to a
  constant in the package that enforces it; make something configurable only
  when an operator would realistically change it.
* Prefer deriving behaviour from what is already configured over adding a
  switch, and then *tell the operator what was derived* (startup banner)
  rather than making them guess.
* Never add: a database, durable queue, message broker, Azure/Graph SDK, web
  or frontend framework, PDF rendering stack, plugin system, admin UI, or
  HTTPS/cert handling. Persistence is out of scope by design — jobs are
  ephemeral and a crash losing them is accepted, not a problem to solve.
* Dependency budget is deliberate and tiny: `go-smtp`, `go-oidc`, `oauth2`.
  Adding anything else needs the owner's agreement first.

## How work is organised

* Work in **work packages**, one pull request each. Finish a package, then
  stop and tell the owner it is ready — they take a short look and merge
  before the next package starts.
* **Subagents implement.** Match the model to the task rather than defaulting
  to the strongest one: a cheaper, faster model handles mechanical,
  well-specified work (config plumbing, REST clients, applying a review's
  cuts), while untrusted-input parsing, authentication and authorization,
  concurrency and test-harness design get the most capable model available.
* Freeze interfaces between packages in writing *before* dispatching parallel
  agents, and give each agent an explicit file scope so they never collide.
* Review order for every package, with fresh subagents that did not write the
  code: **overengineering review first**, apply the cuts, **then** the
  correctness review. Then open the PR.
* Codex reviews PRs automatically; request a Copilot review on every PR as
  well. The two read differently, and the finding that mattered most on work
  package 3 came from Copilot alone. Iterate on what they find. Do not chase
  review convergence — a finding that costs more lines than the risk it
  removes should be declined, with the reasoning on the thread and the thread
  left open for the owner.
* An identical review arriving again is usually the same review re-anchored to
  a new head commit, not a fresh finding. Check the resolved threads before
  acting: re-fixing or re-arguing something already settled wastes a cycle and
  muddies the thread.
* Record decisions (and the reasoning) where the next agent will read them, so
  nothing gets re-litigated by whoever picks up the next package.

## Verification

* Prove it against the real thing, not only unit tests: drive the real SMTP
  listener over a real socket, run the real container read-only, start the
  real binary and read its output. Tests passing is not evidence the appliance
  works.
* Race tests and fuzzing belong on untrusted-input boundaries.
* Report failures plainly, including the ones found after claiming success.

## Repository hygiene

* Public repository: synthetic values only — no real tenant ids, domains,
  addresses or secrets, anywhere, including tests. Keep test credentials in a
  single obviously-fake constant; secret scanners flag scattered literals.
* Commit messages explain *why*, in prose, wrapped. No model names, no tool
  attribution in anything pushed to the repository.
* Keep branch history clean and signed. Squashing a branch is better than
  leaving an intermediate commit that a scanner or a reader will trip over.
* Never log document content, OCR text, tokens, secrets, cookies, whole MIME
  messages, or subjects. A generated credential the operator must see goes to
  stderr directly, so a log level cannot hide it.
* PRs that change the UI include screenshots.

## Talking to the owner

* Interim messages stay short. The one message that matters is "this package
  is ready to merge", with what to look at.
* Ask when something is genuinely unclear, *before* investing in the wrong
  thing — a clarifying question up front is welcome and cheaper than rework.
* Surface a trade-off when it is real (a ceiling in an API, a failure mode
  they will meet in practice). Give a recommendation rather than an
  exhaustive survey of options.
* When overruling a reviewer or an instruction, say so explicitly and why, so
  the owner can reverse it in one sentence.
