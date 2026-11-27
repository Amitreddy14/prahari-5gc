"""Statistical layer: Isolation Forest over windowed behavioural features.

Trained on benign windows only; an event is flagged when its source's current window scores
as an outlier. The threshold is set from the benign score distribution, so the benign
false-positive rate is controlled (not the attack recall), keeping the comparison honest.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from prahari_analytics.detect.rules import Alert
from prahari_analytics.detect.windows import WindowBuilder

WINDOW_NS = 2_000_000_000


@dataclass
class IsolationForestDetector:
    """Window size, target benign false-positive rate (sets the score threshold), and the
    forest's own parameters. `calibrate` fits on benign; `score` flags anomalous windows."""

    window_ns: int = WINDOW_NS
    benign_fp: float = 0.01  # target benign flag rate -> IsolationForest contamination
    n_estimators: int = 200
    random_state: int = 0
    _builder: WindowBuilder = field(init=False, repr=False)
    _model: Any = field(init=False, default=None, repr=False)
    _scaler: Any = field(init=False, default=None, repr=False)
    _keep: Any = field(init=False, default=None, repr=False)  # indices of informative features

    def __post_init__(self) -> None:
        self._builder = WindowBuilder(self.window_ns)

    def calibrate(self, benign: Iterable[dict[str, Any]]) -> IsolationForestDetector:
        import numpy as np  # noqa: PLC0415
        from sklearn.ensemble import IsolationForest  # noqa: PLC0415
        from sklearn.preprocessing import RobustScaler  # noqa: PLC0415

        rows = sorted(benign, key=lambda e: int(e["ts_ns"]))
        builder = WindowBuilder(self.window_ns)
        vectors = [builder.add(ev) for ev in rows]
        if not vectors:
            self._model = None
            return self
        x: Any = np.asarray(vectors, dtype=float)
        # Keep only features that vary in benign. A feature constant across benign gives the
        # forest no way to isolate on it (it can only split within the training range), so
        # keeping it just dilutes the anomaly signal across irrelevant dimensions -- the
        # binary "it's zero in benign" signals are the rules layer's job, not the forest's.
        self._keep = np.flatnonzero(x.std(axis=0) > 1e-9)
        if self._keep.size == 0:
            self._model = None
            return self
        xk = x[:, self._keep]
        # RobustScaler (median/IQR) keeps a large outlier large; StandardScaler lets a few
        # extreme benign windows inflate the std and hide real spikes.
        self._scaler = RobustScaler().fit(xk)
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            contamination=self.benign_fp,
        ).fit(self._scaler.transform(xk))
        self._builder.reset()
        return self

    def reset(self) -> None:
        self._builder.reset()

    def _predict(self, vectors: Any) -> Any:
        import numpy as np  # noqa: PLC0415

        x = self._scaler.transform(np.asarray(vectors, dtype=float)[:, self._keep])
        return self._model.predict(x), self._model.decision_function(x)

    def score(self, ev: dict[str, Any]) -> list[Alert]:
        vector = self._builder.add(ev)
        if self._model is None:
            return []
        labels, scores = self._predict([vector])
        return self._alert(int(labels[0]), float(scores[0]))

    def score_all(self, rows: list[dict[str, Any]]) -> list[list[Alert]]:
        """Causal per-event scoring in one model call: window vectors are built in time
        order (each uses only earlier events), then scored as a single batch."""
        if self._model is None:
            return [[] for _ in rows]
        self._builder.reset()
        labels, scores = self._predict([self._builder.add(ev) for ev in rows])
        return [self._alert(int(lbl), float(s)) for lbl, s in zip(labels, scores, strict=True)]

    def _alert(self, label: int, score: float) -> list[Alert]:
        if label == -1:  # sklearn: -1 is an outlier
            return [Alert("isoforest", f"window is a statistical outlier (score {score:.3f})")]
        return []
