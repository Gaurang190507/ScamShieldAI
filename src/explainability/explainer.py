"""Generates human-interpretable explanations of detected tactics and uncertainty."""

from typing import Dict, Any, List


class TacticalExplainer:
    """Translates raw risk signals into clear behavioral insights for investigators."""

    def generate_explanation(self, assessment: Dict[str, Any]) -> List[str]:
        """Produces bullet-point evidence summaries highlighting why specific risk levels were assigned.

        Args:
            assessment: Output dictionary from RiskEngine.evaluate.

        Returns:
            List of explanatory bullet strings.
        """
        explanations = []
        tactics = assessment.get("detected_tactics", {})

        for tactic, matches in tactics.items():
            explanations.append(f"Identified '{tactic}' tactic: matched phrases {matches}")

        url_flags = assessment.get("url_flags", [])
        for flag in url_flags:
            explanations.append(f"URL flag: {flag}")

        if not explanations:
            explanations.append("No overt manipulation patterns detected.")

        return explanations
