"""The corroboration vocabulary, kept free of imports from the appraisers.

`appraisal` judges corroboration and `corroboration` assembles it, and each needs
the result type and the acknowledgement event types. Keeping those two names here
means the dependency runs one way, instead of the two modules importing each other
and Python resolving the cycle by import order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

PROVIDER_ACK_TYPES = frozenset(
    {
        "provider.acknowledged",
        "provider.confirmed",
        "provider.attestation",
        "provider_acknowledged",
        "provider_confirmed",
    }
)


@dataclass(frozen=True)
class CorroborationResult:
    """What the verifier could establish about external corroboration.

    Every field is a conclusion. None of them is read from a bundle field and
    none of them can be set by a caller of the verifier.
    """

    present: bool = False
    source_party: Optional[str] = None
    source_type: Optional[str] = None
    source_record_id: Optional[str] = None
    source_record_digest: Optional[str] = None
    signer_identity: Optional[str] = None
    signer_identity_verified: bool = False
    independent_of_deployment: bool = False
    subject_binding_valid: bool = False
    provenance_verified: bool = False
    replay_check_passed: bool = False
    cryptographic_integrity_valid: bool = False
    reasons: Tuple[str, ...] = ()

    @property
    def satisfied(self) -> bool:
        """True only when every condition E3 needs has been established."""
        return all(
            (
                self.present,
                self.signer_identity_verified,
                self.independent_of_deployment,
                self.provenance_verified,
                self.subject_binding_valid,
                self.replay_check_passed,
                self.cryptographic_integrity_valid,
            )
        )

    def summary(self) -> str:
        if not self.present:
            return "no provider acknowledgement event in the bundle"
        if self.satisfied:
            return f"corroborated by {self.source_party} ({self.source_record_id})"
        return "acknowledgement not corroborating: " + "; ".join(self.reasons or ("unstated",))
