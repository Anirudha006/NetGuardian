import os
import subprocess
import sys

def run_pytest(args):
    cmd = [sys.executable, "-m", "pytest", "--tb=short"] + args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr

def mutate_and_verify(name, file_path, original_str, mutated_str, test_args):
    print("\n" + "=" * 70)
    print(f"MUTATION AUDIT: {name}")
    print(f"File: {file_path}")
    print(f"Break: {original_str!r}  -->  {mutated_str!r}")
    print("=" * 70)

    with open(file_path, "r", encoding="utf-8") as f:
        orig_content = f.read()

    assert original_str in orig_content, f"Target string not found in {file_path}"

    try:
        broken_content = orig_content.replace(original_str, mutated_str, 1)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(broken_content)

        code, output = run_pytest(test_args)
        print(f"Exit code during mutation (expected != 0): {code}")
        # Print failure summary
        lines = output.splitlines()
        for line in lines:
            if "FAILED" in line or "AssertionError" in line or "assert " in line or "short test summary" in line or "failed" in line:
                print("  " + line)
        assert code != 0, f"CRITICAL: Mutation {name} was NOT caught by tests!"
        print(f"VERDICT: PASS (Test suite successfully detected broken behavior)")
    finally:
        # Always restore exact original content
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(orig_content)
        print(f"Restored {file_path} to clean state.")

    code_post, _ = run_pytest(test_args)
    assert code_post == 0, f"Post-restore check failed for {name}!"
    print(f"Post-restore verification: PASSED (Exit code {code_post})")


if __name__ == "__main__":
    mutate_and_verify(
        name="1. Break Port Scan Threshold Logic",
        file_path="backend/app/detection/rule_engine.py",
        original_str="if u_ports >= port_thresh:",
        mutated_str="if u_ports >= 999999:  # MUTATED",
        test_args=["backend/tests/test_phase3.py", "-k", "test_rule_pipeline_window_evaluation"]
    )

    mutate_and_verify(
        name="2. Remove Admin Role Check on PATCH /api/settings",
        file_path="backend/app/routes/settings.py",
        original_str="    admin: User = Depends(require_admin),",
        mutated_str="    admin: User = Depends(require_analyst_or_admin),  # MUTATED",
        test_args=["backend/tests/test_phase9.py", "-k", "test_role_enforcement_on_every_state_changing_endpoint"]
    )

    mutate_and_verify(
        name="3. Break Health Score Formula",
        file_path="backend/app/services/health_calculator.py",
        original_str="    health_score = max(0.0, min(100.0, round(100.0 - raw_total_penalty, 1)))",
        mutated_str="    health_score = 42.0  # MUTATED",
        test_args=["backend/tests/test_phase9.py", "-k", "test_case_1_normal_traffic_gives_no_alert"]
    )

    print("\nALL 3 MUTATION TESTS PASSED & CLEANLY RESTORED.")
