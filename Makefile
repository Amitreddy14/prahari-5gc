# Run inside the dev container (VS Code: "Reopen in Container") or any Linux box.
# Windows without make: the commands under each target work as-is in the container shell.
.PHONY: help probe probe-asan probe-release tidy fuzz analytics lint check preflight clean

PY ?= python3
FUZZ_SECONDS ?= 60

help:
	@echo "probe          Build + test the C++ probe (GCC, Debug)"
	@echo "probe-asan     Build + test under ASan/UBSan (Clang)"
	@echo "probe-release  Release build + tests"
	@echo "tidy           clang-tidy over probe sources"
	@echo "fuzz           Run the PFCP fuzzer for FUZZ_SECONDS (default 60)"
	@echo "analytics      ruff + mypy + pytest for the Python package"
	@echo "lint           shellcheck + clang-format check"
	@echo "check          Everything CI runs"
	@echo "preflight      Can this Docker host run the 5G testbed?"

probe:
	cd probe && cmake --preset debug && cmake --build --preset debug --parallel && ctest --preset debug

probe-asan:
	cd probe && cmake --preset asan && cmake --build --preset asan --parallel && ctest --preset asan

probe-release:
	cd probe && cmake --preset release && cmake --build --preset release --parallel && ctest --preset release

tidy: probe-asan
	cd probe && clang-tidy -p build/asan src/*.cpp

fuzz:
	cd probe && cmake --preset fuzz && cmake --build --preset fuzz && \
	mkdir -p build/fuzz/corpus && cp fuzz/corpus/pfcp/* build/fuzz/corpus/ && \
	./build/fuzz/fuzz_pfcp -max_total_time=$(FUZZ_SECONDS) build/fuzz/corpus

analytics:
	cd analytics && ruff check . && ruff format --check . && mypy && pytest

lint:
	shellcheck scripts/*.sh
	find probe -path probe/build -prune -o \( -name '*.cpp' -o -name '*.hpp' \) -print | xargs clang-format --dry-run --Werror

check: lint probe-asan probe-release tidy analytics

preflight:
	bash scripts/check-host.sh

clean:
	rm -rf probe/build
