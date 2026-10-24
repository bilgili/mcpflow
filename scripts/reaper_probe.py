# Exit 1 unless process 1 is tini and it reaps orphans.
import os, subprocess, time

for _ in range(4):
    subprocess.run(["sh", "-c", "sleep 0.1 & exit 0"], check=True)
time.sleep(1)

def stat(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    except OSError:
        return None

# Count only zombies whose parent is process 1: the gateway's own short-lived
# children do not make the count flaky.
orphans = [p for p in os.listdir("/proc") if p.isdigit()
           and (s := stat(p)) and s[0] == "Z" and s[1] == "1"]
init = open("/proc/1/comm").read().strip()
print(f"process 1: {init}, unreaped orphans: {len(orphans)}")
raise SystemExit(0 if init == "tini" and not orphans else 1)
