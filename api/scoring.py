"""Passive inference and recommendation using the existing detector and playbook."""
from agent.detector import get_detector, risk_score
from agent.planner import plan_response


class NoOutcomeHistory:
    """Use the existing planner's conservative defaults without simulated feedback."""

    @staticmethod
    def action_stats(_attack_type):
        return {}


def score_features(features, settings):
    detection = get_detector().detect(
        features,
        confidence_threshold=settings["detector"]["confidence_threshold"],
        outlier_threshold=settings["detector"]["outlier_threshold"],
    )
    score = risk_score(detection["attack_type"], detection["confidence"], detection["novelty"])
    recommendation = plan_response(
        NoOutcomeHistory(),
        {
            "final_type": detection["attack_type"],
            "risk": detection["risk"],
            "risk_score": score,
        },
    )
    return {
        "classification": detection["attack_type"],
        "raw_classification": detection["raw_label"],
        "confidence": detection["confidence"],
        "novelty_distance": detection["novelty"],
        "is_unknown": detection["is_unknown"],
        "unknown_reason": detection["unknown_reason"],
        "risk": detection["risk"],
        "risk_score": score,
        "probabilities": detection["probabilities"],
        "recommendation": recommendation["action"],
        "recommendation_reason": recommendation["reason"],
    }
