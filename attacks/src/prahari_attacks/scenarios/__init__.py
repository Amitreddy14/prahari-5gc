"""Registry of attack scenarios, keyed by attack ID (docs/threat-model.md)."""

from __future__ import annotations

from prahari_attacks.scenarios.base import Scenario
from prahari_attacks.scenarios.n4 import (
    EstablishmentFlood,
    RogueAssociation,
    SessionDeletion,
    SessionModificationHijack,
)
from prahari_attacks.scenarios.sbi import NfDeregistration, NrfRecon, RogueNfRegistration, SbiFuzz

SCENARIOS: dict[str, type[Scenario]] = {
    s.attack_id: s
    for s in (
        SessionDeletion,
        SessionModificationHijack,
        EstablishmentFlood,
        RogueAssociation,
        NrfRecon,
        RogueNfRegistration,
        NfDeregistration,
        SbiFuzz,
    )
}

__all__ = ["SCENARIOS", "Scenario"]
