# Triton Inference Server core: prefix match in `IsChildPathEscapingParentPath` lets a model read sibling directories

`IsChildPathEscapingParentPath` in `triton-inference-server/core` decides whether a
path stays inside a directory with `child.rfind(parent, 0) != 0` on canonicalised
strings and no path-separator boundary. A child that canonicalises into a sibling
directory whose name begins with the parent's name (`/models/foo_admin/keys.txt`
against the parent `/models/foo`) is reported as inside. The check was added to
contain `label_filename` path traversal; with the bypass, a model whose
`config.pbtxt` sets `label_filename: "../foo_admin/keys.txt"` loads the sibling's
file as its label list, and the lines come back verbatim in classification
responses.

| | |
|---|---|
| CVE | none claimed (see [Prior coverage](#prior-coverage) on NVIDIA's May 2026 bulletin) |
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-697 (Incorrect Comparison) |
| Project | [`triton-inference-server/core`](https://github.com/triton-inference-server/core), `src/filesystem/api.cc`; shipped in [`triton-inference-server/server`](https://github.com/triton-inference-server/server) builds |
| Affected | the comparison since `7363cfe` (2024-01-11); as a file-read primitive through `label_filename` from core `f2226c0` (2026-01-30, first in core `r26.02` / server v2.66.0) up to core `r26.05` / server v2.69.0 inclusive |
| Fixed in | core `dcb315d9f9` (#497, 2026-05-18) with its operand-order correction `72f3d9b8b2` (#498, 2026-05-19); core `r26.06`; server v2.70.0 (2026-06-26) |
| CVSS v3.1 | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **5.5 Medium**; `AV:N` = 6.5 where the model-load API accepts a client-supplied config |
| Reported by | s1ko ([github.com/s1ko](https://github.com/s1ko), `s1ko@riseup.net`) |

## Scope, stated plainly

- **The attacker needs to control a model's `config.pbtxt`.** Either write access to
  a model directory in the repository (a tenant, a CI pipeline, an imported model),
  or, with `--model-control-mode=explicit`, a client that can call the
  [load API](https://github.com/triton-inference-server/server/blob/r26.05/docs/user_guide/model_management.md)
  with a replacement config, which that document describes. Triton does not authenticate
  clients by default, so the second route is as open as the endpoint is.
- **The reach is bounded.** Only paths that canonicalise under a directory whose
  *name starts with the model directory's name* get through. `models/foo` reaches
  `models/foo_admin`, `models/foo2`, `models/foobar`; it does not reach
  `models/bar`, `/etc`, or the parent. A one-character model name widens it to every
  sibling beginning with that character. The attacker has to know or guess a
  sibling name.
- **The read is line-oriented.** The file is read as text and split on newlines;
  each line becomes a class label. Binary files read as garbage.
- **Before #465 the check did not exist at all** (`label_filename` was joined to the
  model directory unchecked), so for the label path this bug matters only for the
  window in which the incomplete fix was the only protection, core `r26.02`
  through `r26.05`.
- **A second call site exists** — the backend library path in `src/backend_model.cc`
  (from `runtime`) uses the same function. Exploiting it would need a library file in
  a sibling of a backend directory; that was not constructed and is not claimed.
- **Source-level reproduction.** The PoCs are C++ harnesses that copy the function and
  the label loader, plus a differential test of the verbatim function bodies before and
  after the fix. A full `tritonserver` process serving a classification request was not
  run for this advisory.

## Threat model

Multi-tenant or shared model repositories are the realistic setting: one directory
per model under a common root, models contributed by different teams or customers,
a CI job that deploys pushed models into the shared root, or models pulled from a
public hub whose `config.pbtxt` the operator does not read. The tenant (or the
contributor of an imported model) controls the config of its own model and wants
to read a neighbour.

`label_filename` is a documented `ModelOutput` field. At model load,
`LabelProvider::AddLabels` reads the file; on inference, an output requested with
the `classification` parameter returns the top-N labels as strings. That
documented feature is the exfiltration channel; it is not a separate bug.

## Execution

All excerpts are verbatim from core `r26.05` (`e6fcb0c78e072672beab614384fd4f763c302134`,
2026-05-04), the last release line with the flaw.

`src/filesystem/api.cc:403-428`:

```cpp
IsChildPathEscapingParentPath(
    const std::string& child_path, const std::string& parent_path,
    bool* is_escaped)
{
  std::string absolute_child_path;
  std::string absolute_parent_path;
  try {
    absolute_child_path =
        std::filesystem::weakly_canonical(child_path).string();
  }
  catch (const std::exception& e) {
    return Status(
        Status::Code::INVALID_ARG,
        "Invalid path '" + child_path + "': " + e.what());
  }
  try {
    absolute_parent_path = std::filesystem::canonical(parent_path).string();
  }
  catch (const std::exception& e) {
    return Status(
        Status::Code::INVALID_ARG,
        "Nonexistent path '" + parent_path + "': " + e.what());
  }
  // Can use starts_with() over rfind() in C++20.
  *is_escaped = absolute_child_path.rfind(absolute_parent_path, 0) != 0;
  return Status::Success;
}
```

`rfind(x, 0) != 0` is "does not start with". No separator is appended to the
parent, so with the parent `/models/foo`:

| Child (canonical) | `is_escaped` | Correct |
|---|---|---|
| `/models/foo/labels.txt` | false | false |
| `/models/foo_admin/keys.txt` | **false** | true |

`src/model.cc:116-128` is the `label_filename` call site added by #465:

```cpp
    if (!io.label_filename().empty()) {
      auto label_path = JoinPath({model_dir_, io.label_filename()});
      bool is_escaped = false;
      RETURN_IF_ERROR(
          IsChildPathEscapingParentPath(label_path, model_dir_, &is_escaped));
      if (is_escaped) {
        return Status(
            Status::Code::UNSUPPORTED,
            "label file path '" + label_path + "' for output '" + io.name() +
                "' in model '" + Name() + "' is outside model directory");
      }
      RETURN_IF_ERROR(label_provider_->AddLabels(io.name(), label_path));
    }
```

`JoinPath` leaves the `..` in place (an absolute `label_filename` is appended under the
model directory, not honoured), so `models/foo` + `../foo_admin/keys.txt`
canonicalises to `models/foo_admin/keys.txt`, passes the check, and `AddLabels`
(`src/label_provider.cc:55-75`) reads it with `ReadTextFile` and `std::getline`.

The same comparison appears in the second call site, `src/backend_model.cc:368`
(backend library path), and in an inline copy at
`src/model_repository_manager/model_repository_manager.cc:165`
(`if (file_path.rfind(temp_dir, 0) != 0) {`, the repository-agent file-override
check). The fix replaced all three.

### Reproduction

A model repository for a live server would look like this; the harnesses below
exercise the same predicate and label load without needing a GPU build.

```
models/
  foo/            attacker-controlled
    config.pbtxt  label_filename: "../foo_admin/keys.txt"
  foo_admin/
    keys.txt
```

[`poc/run-poc.sh`](poc/run-poc.sh) compiles and runs three C++17 programs (`g++`
required):

- [`poc/path_escape_poc.cc`](poc/path_escape_poc.cc) — the predicate alone, with the
  original function body.
- [`poc/full_chain_poc.cc`](poc/full_chain_poc.cc) — `JoinPath`, the predicate and a
  `LabelProvider` lookalike, ending in the simulated classification response.
- [`poc/differential.cc`](poc/differential.cc) — the verbatim function body from
  `r26.05` and from the corrected fix `72f3d9b`, run side by side over seven cases
  (comments stripped from the extracted bodies, nothing else changed).

```
bash poc/run-poc.sh
```

The differential output ([`poc/expected-output.txt`](poc/expected-output.txt)):

```
case                                           r26.05    72f3d9b   expected
label inside model dir                         allowed   allowed   allowed
file in version subdirectory                   allowed   allowed   allowed
child equals parent                            allowed   allowed   allowed
sibling sharing the name prefix (foo_admin)    allowed   escaped   escaped   <- r26.05 wrong
sibling with unrelated name (bar)              escaped   escaped   escaped
parent of the model dir                        escaped   escaped   escaped
two levels up                                  escaped   escaped   escaped

mismatches r26.05: 1, mismatches 72f3d9b: 0
```

A live-server request, for a deployment where it can be tried (explicit model control
or write access to the repository), is a `POST /v2/models/foo/infer` with
`"outputs": [{"name": "y", "parameters": {"classification": 2}}]`; the response
carries the first lines of `foo_admin/keys.txt` as class labels. That request was not
captured against a running server for this advisory. Run it only against
infrastructure you are authorised to test.

## Detection

Static, before load. A config that points a label file or a runtime outside its own
directory is the indicator:

```
grep -rEn --include=config.pbtxt \
  '(label_filename|runtime)[[:space:]]*:[[:space:]]*"[^"]*\.\.' /path/to/model_repository
```

YARA, for the same on a repository or on config blobs captured from load requests:

```
rule triton_config_label_or_runtime_traversal
{
    meta:
        description = "Triton config.pbtxt whose label_filename or runtime contains a parent-directory component"
        author = "s1ko"
        reference = "CWE-22"
    strings:
        $label = /label_filename\s*:\s*"[^"]*\.\.[\/\\][^"]*"/
        $runtime = /runtime\s*:\s*"[^"]*\.\.[\/\\][^"]*"/
    condition:
        any of them
}
```

Code pattern, Semgrep for C++ (prefix-match containment on path-named operands):

```
rules:
  - id: cpp-path-prefix-containment-without-separator
    languages: [cpp]
    severity: WARNING
    message: containment tested by prefix match on a path without a separator boundary; /a/foo also matches /a/foo_admin
    patterns:
      - pattern-either:
          - pattern: $CHILD.rfind($PARENT, 0) != 0
          - pattern: $CHILD.rfind($PARENT, 0) == 0
      - metavariable-regex:
          metavariable: $PARENT
          regex: (?i).*(path|dir).*
```

Run on core `r26.05` it reports `api.cc:427` and
`model_repository_manager.cc:165`, and also `:423`, which is a containment-style
comparison to review rather than a confirmed instance. It reports nothing on the fixed
`api.cc`. The YARA rule matches a config with `label_filename: "../foo_admin/keys.txt"`
and not one with `label_filename: "labels.txt"`; the `grep` was run on the same two files.

At runtime the server does not log the bypass: a successful load of the sibling's file
is indistinguishable from a normal label load. The attempt that is *blocked* logs
`label file path '...' for output '...' in model '...' is outside model directory`,
which on a fixed server is the line that shows someone probing.

## Mitigation

- **Upgrade to server v2.70.0 / NGC `tritonserver:26.06` or later** (core `r26.06` or
  later). Do not run core between #497 and #498 on `main` (2026-05-18 to
  2026-05-19): as merged, #497 compared the operands the wrong way round
  (`canonical_parent_path.find(canonical_child_path, 0)`) and flagged *legitimate*
  children as escaping; #498 corrected it the next day. Release branches `r26.05` and
  `r26.06` are not affected by that interlude.
- Until upgraded: do not let tenants supply or edit `config.pbtxt` in a shared
  repository; run `--model-control-mode=none` (or keep the load API off untrusted
  networks); name model directories so that none is a string prefix of another
  (`tenant-a-model` / `tenant-b-model`, fixed-width ids); apply the `grep` above as a
  pre-deployment gate.
- Per-tenant repositories on separate paths and, ideally, separate server processes,
  remove the shared parent entirely.
- For any code that tests containment: canonicalise both paths, then compare path
  components (`std::filesystem::relative` and reject `..`), or require the parent plus
  a `/` as the prefix; never compare raw strings.

NIST SP 800-53r5 `SI-10`; OWASP ASVS v4 §12.3.1; CWE-22 mitigation (canonicalise,
then compare components); MITRE ATT&CK T1005 for the read primitive.

## Timeline

| Date | Event |
|---|---|
| 2024-01-11 | `IsChildPathEscapingParentPath` introduced with the prefix comparison (`7363cfe`, "Incorporate runtime into model configuration", #285) |
| 2026-01-30 | #465 "Disallow '..' operator in label paths" merged (`f2226c0`): adds the `label_filename` call site; first in core `r26.02` |
| 2026-04-20 | #491 wraps the function in exception handling (`cec19b9`); comparison unchanged |
| 2026-04-25 | Reported via huntr.com (report `bcda4ff1-038b-4b65-8866-49d235842641`) against core `e93e4a9`. The platform acknowledged it and passed it to internal triage, notified the vendor and marked it published (2026-07-24) without ever validating it; no bounty or credit as of 2026-10-28. Also reported privately to NVIDIA PSIRT. |
| 2026-05-12 | Upstream opens #497 "Modernize Child Path Detection" |
| 2026-05-18 | #497 merged (`dcb315d9f9`) |
| 2026-05-19 | #498 "fix: child path test" merged (`72f3d9b8b2`), correcting the operand order |
| 2026-06-26 | Server v2.70.0 released, built from core `r26.06` (release note: "Hardened model environment unpacking and file-path handling against path traversal") |
| 2026-10-28 | Published here |

This advisory does not claim that #497 was made in response to the report; it records
that #497 was opened 17 days after it.

## Prior coverage

- **Before the report:** none for this comparison. The Triton `core` and `server`
  repositories have no advisory and no issue or pull request mentioning
  `IsChildPathEscapingParentPath` before #497. PR #465 is the earlier, incomplete
  fix of the `label_filename` traversal that this report is a bypass of.
- **After the report:** #497 and #498 are the upstream fix. The server v2.70.0 release
  notes describe it only as "Hardened model environment unpacking and file-path
  handling against path traversal"; they name neither this function nor a CVE.
- **NVIDIA's "NVIDIA Triton Inference Server — May 2026" security bulletin**
  (published 2026-05-19) lists CVE-2026-24206, described by NVD as an authentication
  bypass that might lead to escalation of privileges, denial of service or information
  disclosure. The description names no component, file or version, so this advisory
  does not claim that it corresponds to this issue and does not rely on it.

## References

- Affected branch — https://github.com/triton-inference-server/core/tree/r26.05
- Original incomplete fix — https://github.com/triton-inference-server/core/pull/465
- Fix — https://github.com/triton-inference-server/core/pull/497
- Operand-order correction — https://github.com/triton-inference-server/core/pull/498
- Server v2.70.0 — https://github.com/triton-inference-server/server/releases/tag/v2.70.0

## License

MIT — see [LICENSE](LICENSE).
