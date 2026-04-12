import pandas as pd
import subprocess
import tempfile
import os
import json
import requests
from tqdm import tqdm

MODEL_ENDPOINT = os.environ.get("MODEL_ENDPOINT", "http://localhost:5000")

# ── Query your fine-tuned model ──────────────────────────────────────────────
def query_llm(vulnerable_code: str) -> str:
    try:
        response = requests.post(MODEL_ENDPOINT, json={
            "inputs": f"""### Vulnerable C/C++ Function:
{vulnerable_code}

### Patched Memory-Safe Version:
""",
            "parameters": {
                "max_new_tokens": 512,
                "temperature": 0.2,
                "repetition_penalty": 1.15
            }
        }, timeout=60)
        return response.json().get("generated_text", "")
    except Exception as e:
        return ""

# ── Check if patch compiles ───────────────────────────────────────────────────
def compiles(code: str) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
        f.write(code)
        fname = f.name
    result = subprocess.run(
        ["gcc", "-fsyntax-only", "-w", fname],
        capture_output=True
    )
    os.unlink(fname)
    return result.returncode == 0

# ── Simple token overlap score (like BLEU but simpler) ───────────────────────
def token_overlap(pred: str, gold: str) -> float:
    pred_tokens = set(pred.lower().split())
    gold_tokens = set(gold.lower().split())
    if not gold_tokens:
        return 0.0
    return len(pred_tokens & gold_tokens) / len(gold_tokens)

# ── Main evaluation loop ─────────────────────────────────────────────────────
def evaluate(test_csv: str, sample_size: int = 100):
    df = pd.read_csv(test_csv)
    df = df[df['partition'] == 'test']
    df = df[df['func_before'].notna() & df['func_after'].notna()]
    df = df.sample(min(sample_size, len(df)), random_state=42)

    results = []
    total = len(df)

    for i, row in tqdm(df.iterrows(), total=total, desc="Evaluating"):
        vulnerable = str(row['func_before'])
        gold_patch = str(row['func_after'])
        cve_id     = row.get('CVE ID', 'unknown')
        cwe_id     = row.get('CWE ID', 'unknown')

        # Get model prediction
        predicted_patch = query_llm(vulnerable)

        # Metrics
        compiled    = compiles(predicted_patch) if predicted_patch else False
        overlap     = token_overlap(predicted_patch, gold_patch)
        not_empty   = len(predicted_patch.strip()) > 20

        results.append({
            "cve_id":           cve_id,
            "cwe_id":           cwe_id,
            "predicted":        predicted_patch,
            "gold":             gold_patch,
            "compiles":         compiled,
            "token_overlap":    round(overlap, 3),
            "non_empty_output": not_empty
        })

    # ── Summary report ───────────────────────────────────────────────────────
    results_df = pd.DataFrame(results)

    total          = len(results_df)
    non_empty      = results_df['non_empty_output'].sum()
    compile_pass   = results_df['compiles'].sum()
    avg_overlap    = results_df['token_overlap'].mean()

    report = {
        "total_samples":        total,
        "non_empty_patches":    int(non_empty),
        "non_empty_rate":       f"{100 * non_empty / total:.1f}%",
        "compilation_pass":     int(compile_pass),
        "compilation_rate":     f"{100 * compile_pass / total:.1f}%",
        "avg_token_overlap":    f"{avg_overlap:.3f}",
        "per_cwe": results_df.groupby('cwe_id')['compiles']
                             .mean()
                             .sort_values(ascending=False)
                             .apply(lambda x: f"{100*x:.1f}%")
                             .to_dict()
    }

    # Save everything
    results_df.to_csv("eval_results.csv", index=False)
    with open("eval_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n========== EVALUATION REPORT ==========")
    print(f"Total samples evaluated : {report['total_samples']}")
    print(f"Non-empty patch rate    : {report['non_empty_rate']}")
    print(f"Compilation pass rate   : {report['compilation_rate']}")
    print(f"Avg token overlap       : {report['avg_token_overlap']}")
    print("\nPer CWE compilation rate:")
    for cwe, rate in report['per_cwe'].items():
        print(f"  {cwe}: {rate}")
    print("========================================")

    return report

if __name__ == "__main__":
    evaluate("big-vul-dataset/MSR_data_cleaned.csv", sample_size=100)