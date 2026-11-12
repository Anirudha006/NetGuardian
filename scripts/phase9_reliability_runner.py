import os
import subprocess
import sys
import time

TEST_FILES = [
    "backend/tests/test_backend.py",
    "backend/tests/test_phase2.py",
    "backend/tests/test_phase3.py",
    "backend/tests/test_phase4.py",
    "backend/tests/test_phase5.py",
    "backend/tests/test_phase6.py",
    "backend/tests/test_phase7a.py",
    "backend/tests/test_phase7b.py",
    "backend/tests/test_phase8.py",
    "backend/tests/test_security_audit.py",
    "backend/tests/test_phase9.py",
    "backend/tests/test_phase9_playwright.py",
]

OUTPUT_FILE = os.path.join("docs", "test_output_phase9.txt")

def run_suite_3_times():
    os.makedirs("docs", exist_ok=True)
    run_summaries = []

    for run_num in range(1, 4):
        print(f"\n=== RELIABILITY RUN {run_num}/3 ===", flush=True)
        t0 = time.perf_counter()
        cmd = [sys.executable, "-m", "pytest", "-v", "--tb=short"]
        if run_num == 3:
            cmd.extend(["--cov=app", "--cov-report=term"])
        cmd.extend(TEST_FILES)

        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        elapsed = time.perf_counter() - t0
        full_output = proc.stdout + proc.stderr

        # Extract final summary line
        lines = [ln for ln in full_output.splitlines() if ln.strip()]
        summary_line = lines[-1] if lines else "No output"
        print(f"Run {run_num} Exit Code: {proc.returncode} | Duration: {elapsed:.2f}s | {summary_line}", flush=True)
        run_summaries.append((run_num, proc.returncode, elapsed, summary_line))

        if run_num == 3:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(full_output)
            print(f"Saved complete Run 3 raw output to {OUTPUT_FILE}", flush=True)

    print("\n=== RELIABILITY SUMMARY ===", flush=True)
    for num, code, dur, s in run_summaries:
        print(f"Run {num}: exit={code}, time={dur:.2f}s, summary={s}", flush=True)

    if any(code != 0 for _, code, _, _ in run_summaries):
        sys.exit(1)

if __name__ == "__main__":
    run_suite_3_times()
