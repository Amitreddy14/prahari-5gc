# Run inside the dev container (VS Code: "Reopen in Container") or any Linux box.
# Windows without make: the commands under each target work as-is in the container shell.
.PHONY: help probe probe-asan probe-release tidy fuzz analytics lint check preflight clean \
	testbed-up testbed-down testbed-smoke testbed-profile testbed-logs \
	bench crosscheck probe-events

PY ?= python3
FUZZ_SECONDS ?= 60

help:
	@echo "probe          Build + test the C++ probe (GCC, Debug)"
	@echo "probe-asan     Build + test under ASan/UBSan (Clang)"
	@echo "probe-release  Release build + tests"
	@echo "tidy           clang-tidy over probe sources"
	@echo "fuzz           Run every fuzzer for FUZZ_SECONDS each (default 60)"
	@echo "bench          Probe throughput (PFCP + NGAP) on PCAP (default: the N4 fixture)"
	@echo "crosscheck     Probe vs tshark, field by field, on CROSSCHECK_PCAPS (all fixtures)"
	@echo "probe-events   Follow live probe events from the running testbed"
	@echo "analytics      ruff + mypy + pytest for the Python package"
	@echo "lint           shellcheck + clang-format check"
	@echo "check          Everything CI runs"
	@echo "preflight      Can this Docker host run the 5G testbed?"
	@echo "testbed-up     Build and start the 5G testbed (needs testbed/.env)"
	@echo "testbed-smoke  End-to-end checks on the running testbed"
	@echo "testbed-profile CPU/RAM per container at 10/50/100 UEs"
	@echo "testbed-logs   Follow AMF, SMF, gNB and UE logs"
	@echo "testbed-down   Stop the testbed (keeps the subscriber DB)"

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
	for f in pfcp pfcp_ie frame ngap nas http2 sbi sbi_flow; do \
	  mkdir -p build/fuzz/corpus-$$f && cp fuzz/corpus/$$f/* build/fuzz/corpus-$$f/ && \
	  ./build/fuzz/fuzz_$$f -max_total_time=$(FUZZ_SECONDS) build/fuzz/corpus-$$f || exit 1; \
	done

PCAP ?= probe/tests/data/n4-lifecycle.pcap
CROSSCHECK_PCAPS ?= probe/tests/data/n4-lifecycle.pcap probe/tests/data/n2-registration.pcap \
                    probe/tests/data/sbi-registration.pcap

bench: probe-release
	./probe/build/release/prahari-probe bench --pcap $(PCAP) --filter "udp port 8805 or sctp or tcp port 7777" --repeat 2000

crosscheck: probe-release
	python3 probe/tools/crosscheck_tshark.py --probe probe/build/release/prahari-probe $(CROSSCHECK_PCAPS)

probe-events:
	tail -f testbed/events/events.jsonl

analytics:
	cd analytics && ruff check . && ruff format --check . && mypy && pytest

analytics-contract: probe-release
	cd analytics && PRAHARI_PROBE_BIN=../probe/build/release/prahari-probe pytest tests/test_probe_output.py

lint:
	shellcheck scripts/*.sh testbed/scripts/*.sh testbed/docker/*.sh
	find probe -path probe/build -prune -o \( -name '*.cpp' -o -name '*.hpp' \) -print | xargs clang-format --dry-run --Werror

check: lint probe-asan probe-release tidy analytics analytics-contract crosscheck

preflight:
	bash scripts/check-host.sh

clean:
	rm -rf probe/build

testbed/.env:
	cp testbed/.env.example testbed/.env

testbed-up: testbed/.env
	cd testbed && docker compose up -d --build

testbed-smoke:
	bash testbed/scripts/smoke.sh

testbed-profile:
	bash testbed/scripts/profile.sh

testbed-logs:
	cd testbed && docker compose logs -f amf smf gnb ue

testbed-down:
	cd testbed && docker compose down
