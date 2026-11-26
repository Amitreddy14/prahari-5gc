"""Benign generator: command shapes, UE addressing, pacing, error tolerance."""

from __future__ import annotations

import random
import threading

from prahari_campaign.benign import BenignConfig, BenignGenerator


def _gen(**kw: object) -> tuple[BenignGenerator, list[tuple[str, str]]]:
    calls: list[tuple[str, str]] = []
    cfg = BenignConfig(ue_count=3, **kw)  # type: ignore[arg-type]
    gen = BenignGenerator(cfg, lambda imsi, cmd: calls.append((imsi, cmd)) or "")
    return gen, calls


def test_imsis_are_sequential_15_digit() -> None:
    gen, _ = _gen()
    assert gen.imsis() == ["001010000000001", "001010000000002", "001010000000003"]


def test_step_issues_a_known_command_to_a_real_ue() -> None:
    gen, calls = _gen(seed=5)
    valid_prefixes = {a.split()[0] for a, _ in BenignConfig().actions}
    for _ in range(40):
        imsi, cmd = gen.step(random.Random(gen.cfg.seed))
        assert imsi in gen.imsis()
        assert cmd.split()[0] in valid_prefixes
    assert calls  # commands actually went to the runner


def test_counts_track_actions_by_verb() -> None:
    gen, _ = _gen()
    rng = random.Random(0)
    for _ in range(50):
        gen.step(rng)
    assert sum(gen.counts.values()) == 50
    assert gen.counts.keys() <= {"ps-establish", "ps-release-all", "ps-list", "status"}


def test_a_failing_ue_does_not_stop_the_generator() -> None:
    def boom(imsi: str, cmd: str) -> str:
        raise RuntimeError("UE not ready")

    gen = BenignGenerator(BenignConfig(ue_count=2), boom)
    gen.step(random.Random(1))
    assert gen.errors == 1
    assert sum(gen.counts.values()) == 0


def test_run_loops_until_stopped() -> None:
    gen, _calls = _gen(rate=0.0)
    stop = threading.Event()
    issued = {"n": 0}

    def fake_sleep(_: float) -> None:  # unused at rate 0
        pass

    def driver() -> None:
        # Let it issue a few, then stop.
        while issued["n"] < 5:
            issued["n"] = sum(gen.counts.values()) + gen.errors
        stop.set()

    t = threading.Thread(target=driver)
    t.start()
    summary = gen.run(stop, sleep=fake_sleep)
    t.join()
    assert summary["commands"] >= 5
    assert summary["errors"] == 0
