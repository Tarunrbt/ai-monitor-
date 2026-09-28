import ctypes
import os
import time

# Give this process a unique Linux process name.
try:
    libc = ctypes.CDLL(None)
    PR_SET_NAME = 15
    libc.prctl(PR_SET_NAME, b"mosgm_worker", 0, 0, 0)
except Exception:
    pass

print(f"mosgm_worker started, PID={os.getpid()}", flush=True)

# Phase 1: normal
print("NORMAL phase: 120 seconds", flush=True)
time.sleep(120)

# Phase 2: CPU spike
print("CPU SPIKE phase: 30 seconds", flush=True)
end = time.time() + 30

while time.time() < end:
    x = 0
    for i in range(500000):
        x += i * i

# Phase 3: cooldown
print("COOLDOWN phase: 30 seconds", flush=True)
time.sleep(30)

print("mosgm_worker finished", flush=True)
