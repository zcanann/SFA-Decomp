import subprocess
import time

CMD = 'codex exec --yolo "Follow the instructions in AGENTS.MD. NEVER ask the user for input. Simply follow the instructions and move towards the objective of decompiling SFA. Pay careful attention to any important rules."'
TIMEOUT_SECONDS = 25 * 60
CYCLE_DELAY = 10

while True:
    proc = subprocess.Popen(CMD, shell=True)
    try:
        proc.wait(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        subprocess.run(
            f"taskkill /F /T /PID {proc.pid}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    time.sleep(CYCLE_DELAY)
