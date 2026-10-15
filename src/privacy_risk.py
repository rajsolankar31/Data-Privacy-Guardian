import pandas as pd
import numpy as np
from typing import Dict, Any, List


def calculate_risk_assessment(
    original_df: pd.DataFrame,
    protected_df: pd.DataFrame,
    detected_findings: pd.DataFrame,
    column_actions: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Computes explainable privacy risk metrics, distinguishing direct identifiers,
    quasi-identifiers (re-identification risk / k-anonymity estimation),
    and sensitive attributes.
    """
    if detected_findings.empty or original_df.empty:
        return {
            "overall_risk_score": 0.0,
            "risk_level": "Low",
            "direct_ids_count": 0,
            "direct_ids_exposed": 0,
            "quasi_ids_count": 0,
            "quasi_ids_exposed": 0,
            "sensitive_attrs_count": 0,
            "sensitive_attrs_exposed": 0,
            "coverage_percentage": 100.0,
            "k_anonymity_estimate": len(protected_df) if not protected_df.empty else 0,
            "reidentification_risk": 0.0,
            "details": [],
            "recommendations": ["No sensitive attributes detected by current rules."]
        }

    detected_cols = detected_findings["Column"].unique().tolist()
    
    # Categorize detected columns by Role
    role_map = {}
    for _, row in detected_findings.iterrows():
        role = row.get("Role", "Quasi-Identifier")
        role_map[row["Column"]] = role

    direct_ids = [c for c in detected_cols if role_map.get(c) == "Direct Identifier"]
    quasi_ids = [c for c in detected_cols if role_map.get(c) == "Quasi-Identifier"]
    sensitive_attrs = [c for c in detected_cols if role_map.get(c) == "Sensitive Attribute"]

    # Check exposure in protected_df
    # A column is considered "exposed" if it is present in protected_df and NOT protected, or protected minimally
    direct_exposed = []
    for col in direct_ids:
        if col in protected_df.columns:
            action = column_actions.get(col, {}).get("method")
            if action not in ["Redact", "Remove", "Pseudonymize", "Mask"]:
                direct_exposed.append(col)

    quasi_exposed = []
    for col in quasi_ids:
        if col in protected_df.columns:
            action = column_actions.get(col, {}).get("method")
            if action not in ["Remove", "Generalize", "Redact"]:
                quasi_exposed.append(col)

    sensitive_exposed = []
    for col in sensitive_attrs:
        if col in protected_df.columns:
            action = column_actions.get(col, {}).get("method")
            if action not in ["Remove", "Redact", "Generalize"]:
                sensitive_exposed.append(col)

    # Calculate k-anonymity estimate over remaining quasi-identifiers
    remaining_quasi = [c for c in quasi_ids if c in protected_df.columns]
    k_anon = 1
    reidentification_risk = 0.0
    if remaining_quasi and len(protected_df) > 0:
        try:
            # Group by quasi-identifiers to find equivalence classes
            class_sizes = protected_df.groupby(remaining_quasi, dropna=False).size()
            k_anon = int(class_sizes.min()) if not class_sizes.empty else 1
            # Proportion of records with class size == 1 (unique records)
            unique_records = (class_sizes == 1).sum()
            reidentification_risk = round(float(unique_records / len(protected_df)) * 100, 2)
        except Exception:
            k_anon = 1
            reidentification_risk = 50.0

    # Risk Scoring Formula (0 to 100 scale)
    # Direct IDs exposed: 40 pts each (capped at 60)
    # Re-identification risk from quasi-identifiers: up to 30 pts
    # Sensitive attributes unmitigated: 10 pts each (capped at 20)
    risk_score = 0
    if direct_exposed:
        risk_score += min(len(direct_exposed) * 35, 60)
    else:
        risk_score += 0

    risk_score += (reidentification_risk / 100.0) * 30

    if sensitive_exposed:
        risk_score += min(len(sensitive_exposed) * 10, 20)

    risk_score = min(round(risk_score, 1), 100.0)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Coverage
    total_detected = len(detected_cols)
    addressed = sum(1 for c in detected_cols if c in column_actions)
    coverage = round((addressed / total_detected) * 100, 1) if total_detected > 0 else 100.0

    # Recommendations
    recommendations = []
    if direct_exposed:
        recommendations.append(
            f"Direct identifiers ({', '.join(direct_exposed)}) remain exposed in plain text. "
            f"Apply Redaction, Masking, or Removal immediately."
        )
    if reidentification_risk > 20:
        recommendations.append(
            f"Quasi-identifier combination yields a high re-identification risk ({reidentification_risk}% unique records, min k={k_anon}). "
            f"Generalize or bin attributes like age, location, and dates."
        )
    if sensitive_exposed:
        recommendations.append(
            f"Sensitive attributes ({', '.join(sensitive_exposed)}) remain ungeneralized. "
            f"Ensure data sharing agreements allow sharing these, or apply range generalization."
        )
    if not recommendations:
        recommendations.append("Good privacy protection posture! All detected risk vectors have mitigations applied.")

    return {
        "overall_risk_score": risk_score,
        "risk_level": risk_level,
        "direct_ids_count": len(direct_ids),
        "direct_ids_exposed": len(direct_exposed),
        "quasi_ids_count": len(quasi_ids),
        "quasi_ids_exposed": len(quasi_exposed),
        "sensitive_attrs_count": len(sensitive_attrs),
        "sensitive_attrs_exposed": len(sensitive_exposed),
        "coverage_percentage": coverage,
        "k_anonymity_estimate": k_anon,
        "reidentification_risk": reidentification_risk,
        "direct_exposed_list": direct_exposed,
        "quasi_exposed_list": quasi_exposed,
        "recommendations": recommendations,
    }
