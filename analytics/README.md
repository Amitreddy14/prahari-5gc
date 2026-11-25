# prahari-analytics

The Python half of Prahari-5GC: it consumes the probe's events from Kafka, scores
them for attacks, evaluates the detectors, and hands alerts to the triage agent.

Phase 0 ships the event contract (`prahari_analytics.events`), which must stay in
lock-step with `../schemas/event.v1.schema.json`. A test fails if they drift.

```bash
cd analytics
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```
