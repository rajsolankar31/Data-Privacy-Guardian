import pandas as pd
import numpy as np
from typing import Dict, Any, List


def evaluate_utility(
    original_df: pd.DataFrame,
    protected_df: pd.DataFrame
) -> Dict[str, Any]:
    """
    Evaluates analytical utility preservation between original and protected datasets:
    - Shape & completeness retention
    - Numeric distribution metrics (mean, std deviations, relative error)
    - Categorical entropy / distinct value retention
    - Overall utility preservation index
    """
    if original_df.empty:
        return {
            "rows_retained_pct": 0.0,
            "columns_retained_pct": 0.0,
            "overall_utility_score": 0.0,
            "numeric_metrics": [],
            "categorical_metrics": [],
            "summary": "Original dataset is empty."
        }

    rows_retained = (len(protected_df) / len(original_df)) * 100 if len(original_df) > 0 else 0
    cols_retained = (len(protected_df.columns) / len(original_df.columns)) * 100 if len(original_df.columns) > 0 else 0

    numeric_metrics = []
    num_scores = []

    # Common numeric columns present in both datasets
    common_cols = [c for c in original_df.columns if c in protected_df.columns]
    
    for col in common_cols:
        orig_s = pd.to_numeric(original_df[col], errors="coerce")
        prot_s = pd.to_numeric(protected_df[col], errors="coerce")

        if orig_s.notna().sum() > 2:
            orig_mean = float(orig_s.mean())
            orig_std = float(orig_s.std())
            
            if prot_s.notna().sum() > 2:
                prot_mean = float(prot_s.mean())
                prot_std = float(prot_s.std())
                
                # Mean Relative Difference
                mean_diff = abs(orig_mean - prot_mean) / (abs(orig_mean) + 1e-6)
                score = max(0.0, 100.0 - (mean_diff * 100.0))
                num_scores.append(score)

                numeric_metrics.append({
                    "Column": str(col),
                    "Original Mean": round(orig_mean, 2),
                    "Protected Mean": round(prot_mean, 2),
                    "Original Std": round(orig_std, 2),
                    "Protected Std": round(prot_std, 2),
                    "Mean Retention Score": f"{round(score, 1)}%"
                })
            else:
                # Transformed into non-numeric (e.g. generalized into strings like '20-29' or redacted)
                num_scores.append(65.0)  # Generalized retains grouped utility
                numeric_metrics.append({
                    "Column": str(col),
                    "Original Mean": round(orig_mean, 2),
                    "Protected Mean": "Transformed / Binned",
                    "Original Std": round(orig_std, 2),
                    "Protected Std": "N/A",
                    "Mean Retention Score": "Binned / Formatted"
                })

    categorical_metrics = []
    cat_scores = []
    for col in common_cols:
        orig_s = original_df[col].dropna()
        prot_s = protected_df[col].dropna()
        
        orig_unique = int(orig_s.nunique())
        prot_unique = int(prot_s.nunique())

        if orig_unique > 0:
            ratio = min(1.0, prot_unique / orig_unique) * 100
            cat_scores.append(ratio)
            categorical_metrics.append({
                "Column": str(col),
                "Original Unique Count": orig_unique,
                "Protected Unique Count": prot_unique,
                "Diversity Retention": f"{round(ratio, 1)}%"
            })

    # Overall Utility Score Calculation
    # Weight: 40% column retention, 30% numeric retention, 30% categorical diversity
    avg_num_score = float(np.mean(num_scores)) if num_scores else 100.0
    avg_cat_score = float(np.mean(cat_scores)) if cat_scores else 100.0

    overall_utility = (
        (cols_retained * 0.4) +
        (avg_num_score * 0.3) +
        (avg_cat_score * 0.3)
    )
    overall_utility = min(100.0, max(0.0, round(overall_utility, 1)))

    return {
        "rows_retained_pct": round(rows_retained, 1),
        "columns_retained_pct": round(cols_retained, 1),
        "overall_utility_score": overall_utility,
        "numeric_metrics": pd.DataFrame(numeric_metrics) if numeric_metrics else pd.DataFrame(),
        "categorical_metrics": pd.DataFrame(categorical_metrics) if categorical_metrics else pd.DataFrame(),
    }
