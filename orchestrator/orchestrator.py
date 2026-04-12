import subprocess
import json
import requests
import os
import sys

# ── Config ──────────────────────────────────────────────────────────────────
SEMGREP_RULES   = "p/c"          # free C/C++ ruleset
# MODEL_ENDPOINT  = os.environ.get("MODEL_ENDPOINT", "http://localhost:5000")   # your Kaggle ngrok URL
MODEL_ENDPOINT = "https://licking-idealness-decimeter.ngrok-free.dev/"
EXCEPTION_FILE  = ".secops-exceptions.yaml"

# ── 1. Run SAST ──────────────────────────────────────────────────────────────
def run_semgrep(target_path: str) -> list[dict]:
    result = subprocess.run(
        ["semgrep", "--config", SEMGREP_RULES, target_path, "--json"],
        capture_output=True, text=True
    )
    findings = json.loads(result.stdout).get("results", [])
    print(f"[SAST] Found {len(findings)} findings.")
    return findings

# ── 2. Extract vulnerable snippet ────────────────────────────────────────────
def extract_function_snippet(filepath: str, line: int) -> str:
    with open(filepath) as f:
        lines = f.readlines()
    # Grab 40 lines around the finding (crude but works for prototype)
    start = max(0, line - 5)
    end   = min(len(lines), line + 35)
    return "".join(lines[start:end])

# ── 3. Load exemption manifest ───────────────────────────────────────────────
def load_exceptions() -> dict:
    try:
        import yaml
        with open(EXCEPTION_FILE) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

def is_exempt(filepath: str, rule_id: str, exceptions: dict) -> bool:
    exempt_files = exceptions.get("exempt_files", [])
    exempt_rules = exceptions.get("exempt_rules", [])
    return filepath in exempt_files or rule_id in exempt_rules

# ── 4. Query your fine-tuned model ───────────────────────────────────────────
def query_llm(vulnerable_code: str) -> str:
    prompt = f"""### Vulnerable C/C++ Function:
{vulnerable_code}

### Patched Memory-Safe Version:
"""
    response = requests.post(MODEL_ENDPOINT, json={
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 512,
            "temperature": 0.2,
            "repetition_penalty": 1.15
        }
    })
    return response.json().get("generated_text", "")

# ── 5. Write patch as a new file for review ──────────────────────────────────
def write_patch(filepath: str, patch: str, finding_id: str):
    patch_path = filepath.replace(".c", f"_patch_{finding_id}.c")
    with open(patch_path, "w") as f:
        f.write(patch)
    print(f"[PATCH] Written to {patch_path}")
    return patch_path

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "src/"
    exceptions = load_exceptions()
    findings = run_semgrep(target)

    if not findings:
        print("[OK] No vulnerabilities found.")
        return

    patches = []
    for finding in findings:
        filepath = finding["path"]
        line     = finding["start"]["line"]
        rule_id  = finding["check_id"]

        print(f"\n[VULN] {rule_id} in {filepath}:{line}")

        # Check exemption manifest first
        if is_exempt(filepath, rule_id, exceptions):
            print(f"[EXEMPT] Skipping — matched exception manifest.")
            continue

        # Check for in-code exemption tag
        snippet = extract_function_snippet(filepath, line)
        if "secops-ignore" in snippet:
            print(f"[EXEMPT] secops-ignore tag detected in code.")
            continue

        # Send to your fine-tuned model
        print(f"[LLM] Sending to model...")
        patch = query_llm(snippet)

        patch_path = write_patch(filepath, patch, rule_id.split(".")[-1])
        patches.append({"original": filepath, "patch": patch_path, "rule": rule_id})

    # Write summary for CI
    with open("patch_summary.json", "w") as f:
        json.dump(patches, f, indent=2)
    print(f"\n[DONE] {len(patches)} patches generated → patch_summary.json")

if __name__ == "__main__":
    main()