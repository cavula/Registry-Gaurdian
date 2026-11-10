"""Offline Trivy result fixtures; no subprocess or registry access."""

from guardian.scanning.defender import DefenderFixtures


class TrivyFixtures(DefenderFixtures):
    """Use the normalized fixture format for fallback results."""

    source = "trivy"
