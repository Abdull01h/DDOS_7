import requests
import threading
import time
import json
from collections import defaultdict

print("\n========== L7 SECURITY & FIREWALL TEST ==========")
print("⚠️  Use ONLY on your own website or authorized target\n")

# ================= INPUT =================
TARGET_URL = input("🌐 Website URL (https://example.com): ").strip()
TARGET_IP  = input("🖥️  Server IP (optional, press Enter to skip): ").strip()
DURATION   = int(input("⏱️  Test duration (seconds): "))
THREADS    = int(input("🧵 Concurrent threads/users: "))

# ================ GLOBAL =================
stop_test = False
lock = threading.Lock()

stats = {
    "target_url": TARGET_URL,
    "target_ip": TARGET_IP if TARGET_IP else "default",
    "duration_sec": DURATION,
    "threads": THREADS,
    "start_time": time.ctime(),
    "end_time": "",
    "total_requests": 0,
    "status_codes": defaultdict(int),
    "timeouts": 0,
    "avg_response_time": 0,
    "firewall_indicators": [],
    "possible_issues": [],
    "fix_recommendations": []
}

response_times = []

headers = {
    "User-Agent": "Mozilla/5.0 (Android; L7-Security-Test)",
    "Accept": "*/*",
    "Connection": "close"
}

# ================= WORKER =================
def worker(tid):
    global stats
    while not stop_test:
        try:
            start = time.time()

            r = requests.get(
                TARGET_URL,
                headers=headers,
                timeout=10
            )

            elapsed = round(time.time() - start, 3)

            with lock:
                stats["total_requests"] += 1
                stats["status_codes"][str(r.status_code)] += 1
                response_times.append(elapsed)

                # Firewall / WAF signal detection
                if r.status_code in [403, 406, 429]:
                    stats["firewall_indicators"].append({
                        "thread": tid,
                        "status": r.status_code,
                        "headers_hint": dict(r.headers)
                    })

            print(f"[T{tid}] {r.status_code} | {elapsed}s")

        except requests.exceptions.Timeout:
            with lock:
                stats["total_requests"] += 1
                stats["timeouts"] += 1
            print(f"[T{tid}] TIMEOUT")

        except Exception as e:
            with lock:
                stats["total_requests"] += 1
            print(f"[T{tid}] ERROR")

# ================= RUN =================
threads = []
start_ts = time.time()

print("\n🚀 Test started...\n")

for i in range(THREADS):
    t = threading.Thread(target=worker, args=(i + 1,))
    t.start()
    threads.append(t)

while time.time() - start_ts < DURATION:
    time.sleep(1)

stop_test = True
for t in threads:
    t.join()

stats["end_time"] = time.ctime()

# ================= ANALYSIS =================
if response_times:
    stats["avg_response_time"] = round(
        sum(response_times) / len(response_times), 3
    )

codes = stats["status_codes"]

# --- Issue detection ---
if "429" in codes:
    stats["possible_issues"].append(
        "Rate limiting triggered during normal traffic"
    )
    stats["fix_recommendations"].append(
        "Tune rate‑limit rules (per IP / per session) to avoid false positives"
    )

if "403" in codes or "406" in codes:
    stats["possible_issues"].append(
        "WAF/Firewall blocking legitimate requests"
    )
    stats["fix_recommendations"].append(
        "Review WAF rules, User‑Agent filtering, and false‑positive rules"
    )

if "500" in codes or "502" in codes or "503" in codes:
    stats["possible_issues"].append(
        "Server errors under load"
    )
    stats["fix_recommendations"].append(
        "Optimize backend code, database queries, caching, or increase resources"
    )

if stats["timeouts"] > 0:
    stats["possible_issues"].append(
        "Server response timeout under load"
    )
    stats["fix_recommendations"].append(
        "Use caching, CDN, load balancer, or increase server capacity"
    )

if not stats["possible_issues"]:
    stats["possible_issues"].append(
        "No critical security or performance issue detected in this test window"
    )
    stats["fix_recommendations"].append(
        "Continue monitoring and test with different traffic patterns"
    )

# ================= SAVE REPORT =================
with open("security_report.json", "w") as f:
    json.dump(stats, f, indent=4)

print("\n✅ Test completed successfully")
print("📄 Report saved as: security_report.json")
print("🔍 Open the report to see detected issues & fix suggestions")
