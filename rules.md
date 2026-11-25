# rules.md — rulebook for anyone (human or AI) writing code here

Read this before changing anything. If a rule blocks you, change the rule in a PR
with a reason. Do not quietly break it.

## 1. Scope and workflow

- Work one task from `task.md` at a time. Finish it (code + tests + docs) before starting the next.
- Every phase ends green: build, tests, lint, tidy and fuzz-smoke pass in CI.
- Log decisions, bugs and surprises in `memory.md` as they happen, newest first.
- A decision that is hard to reverse gets an ADR in `docs/adr/`.
- Git: branch per phase (`phase-N-<slug>`), PR into `main`, tag `phase-N` after merge. No AI co-author or attribution lines in commits or PRs.

## 2. C++ (probe/)

**Do**
- C++20, CMake presets, Ninja. Build warning-free under `cmake/Warnings.cmake` with `-Werror`.
- Read every byte through `prahari::ByteReader`. Take input as `std::span<const std::uint8_t>`.
- Return `prahari::Result<T>` from decoders. Malformed input is an expected outcome.
- Mark functions `noexcept` and `[[nodiscard]]` where it holds.
- Add, for every decoder: spec-built test vectors, every-prefix truncation test, a libFuzzer target with seed corpus.
- Keep hot paths allocation-free where reasonable; measure before optimising.

**Don't**
- No raw pointer arithmetic, `memcpy` into structs, or `reinterpret_cast` on packet data.
- No exceptions or `assert` triggered by packet contents.
- No `using namespace std;`, no macros for logic, no global mutable state.
- No new third-party dependency without an ADR line (allowed today: libpcap, nghttp2, librdkafka, OpenSSL, GoogleTest).

## 3. Python (analytics/, attacks/, triage/, console/)

**Do**
- Python 3.11+, type hints everywhere, `mypy --strict` clean, `ruff` clean.
- pydantic v2 models at every boundary (Kafka in/out, API in/out, LLM output).
- Seed every RNG; record seeds and git SHA with every experiment result.
- Evaluation code never sees test labels during training. Splits are by run and by time, never random over events.

**Don't**
- No notebooks as source of truth. Notebooks may only call into the package.
- No `pickle` for anything loaded from outside the repo (use safetensors / JSON).
- No reported metric that a script in the repo cannot regenerate.

## 4. Event contract

- `schemas/event.v1.schema.json` is the source of truth. Change it first, then both producers and consumers, in one PR.
- Breaking change ⇒ new topic and schema version (`v2`), never an in-place edit.
- `labels` exist only in testbed datasets. The live detector must not read them (a test enforces this from Phase 5).

## 5. Security and privacy (non-negotiable)

- Never emit or log a SUPI/IMSI/SUCI in clear. Use `supi_hash` (HMAC-SHA256, key ≥ 16 bytes from env).
- Never commit pcaps, datasets with identifiers, keys, or `.env`. The one exception is small
  test fixtures in `probe/tests/data/` cut from the testbed, whose identities are synthetic
  test-PLMN values, each documented in that folder's README.
- Attack tooling targets only the local testbed. Injector refuses targets outside `172.22.0.0/24` (enforced in code, Phase 4).
- Console/API: auth on every route, rate limiting, strict CORS, input validation, security headers, no debug mode outside dev.
- No service binds to a host port unless it must; MongoDB and Kafka stay internal.
- The LLM triage agent is advisory only. It never runs commands or changes configuration, and its input is treated as untrusted (prompt-injection-safe templating, schema-validated output).
- Keep dependencies patched; CI will gain `pip-audit` and dependency review in Phase 8.

## 6. Error handling

- C++: decode errors → `Result`; I/O and setup errors → log + non-zero exit code (sysexits-style).
- Python: raise specific exceptions; never `except Exception: pass`. Log with structured context (`run_id`, `event_id`).
- Every service fails closed and visibly (health check red), never silently.

## 7. Documentation

- Public headers and modules get a top comment stating what spec section they implement.
- Measured numbers go in README only when produced by a committed script, with hardware noted.
- Claims stay honest: this is a laptop testbed with a simulated RAN, not carrier-grade equipment.
