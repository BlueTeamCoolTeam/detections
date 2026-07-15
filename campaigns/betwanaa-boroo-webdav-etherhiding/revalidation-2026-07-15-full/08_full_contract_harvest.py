#!/usr/bin/env python3
"""
Phase 2 (scale-up): for every one of the 1,816 freshly-confirmed compromised
apex domains (06_urlscan_site_enumeration_fresh_RAW.json), fetch the site's
authenticated urlscan result JSON and extract the eth_call `to` address the
injected loader queries against bsc-testnet-rpc.publicnode.com - the site's
stage-1 (or equivalent) contract address.

This scales the report's original 10-contract/24-site manual sample up to
the full 1,816-site population. Checkpointed to a JSONL file (one line per
site, appended as results arrive, writes serialised through a lock) so the
run is resumable if interrupted - does not require rerunning already-
completed sites.

v2: rewritten for concurrency after the first (serial, one request at a
time) version proved far too slow - each result fetch takes ~3.5-4s on its
own (results run ~500-700KB), so serial + a fixed 0.7s inter-request sleep
was paced for request COUNT/minute, not accounting for how long each
request itself takes to complete; it was on pace to take several hours.
This version uses a small thread pool (respecting urlscan's advertised
concurrency limit of 10 - see 06's rate-limit header capture) with a
requests.Session per worker for connection reuse.
"""
import json
import time
import os
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

KEY_PATH = r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key"
with open(KEY_PATH, encoding="utf-8") as f:
    API_KEY = f.read().strip()

HEADERS = {"API-Key": API_KEY, "User-Agent": "blueteam.cool-revalidation/1.0"}
CHECKPOINT = "08_full_contract_harvest_CHECKPOINT.jsonl"
WORKERS = 8

with open("06_urlscan_site_enumeration_fresh_RAW.json", encoding="utf-8") as f:
    raw = json.load(f)

latest_by_apex = {}
for r in raw["results"]:
    apex = (r.get("page", {}).get("apexDomain") or r.get("page", {}).get("domain") or "").lower()
    if not apex:
        continue
    ts = r.get("task", {}).get("time")
    uuid = r.get("task", {}).get("uuid")
    if not ts or not uuid:
        continue
    if apex not in latest_by_apex or ts > latest_by_apex[apex][0]:
        latest_by_apex[apex] = (ts, uuid)

print(f"Total unique apex domains to process: {len(latest_by_apex)}")

done = set()
if os.path.exists(CHECKPOINT):
    with open(CHECKPOINT, encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
                done.add(rec["apex"])
            except Exception:
                continue
print(f"Already checkpointed: {len(done)}")

remaining = [(apex, uuid) for apex, (ts, uuid) in latest_by_apex.items() if apex not in done]
print(f"Remaining to fetch: {len(remaining)}")

write_lock = threading.Lock()
thread_local = threading.local()


def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        thread_local.session.headers.update(HEADERS)
    return thread_local.session


def extract_contract(result_json):
    requests_list = result_json.get("data", {}).get("requests", [])
    for r in requests_list:
        req_data = r.get("request", {}).get("request", {})
        url = req_data.get("url", "")
        post = req_data.get("postData", "")
        if "bsc-testnet-rpc.publicnode.com" in url and post:
            try:
                body = json.loads(post)
            except Exception:
                continue
            # body may be a single JSON-RPC object or a batch (list of objects)
            candidates = body if isinstance(body, list) else [body]
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                if item.get("method") == "eth_call":
                    params = item.get("params", [])
                    if params and isinstance(params[0], dict):
                        return params[0].get("to"), item.get("id")
    return None, None


def fetch_one(apex, uuid):
    session = get_session()
    url = f"https://urlscan.io/api/v1/result/{uuid}/"
    for attempt in range(4):
        try:
            resp = session.get(url, timeout=20)
        except requests.RequestException as e:
            return {"apex": apex, "uuid": uuid, "error": f"request exception: {e}"}
        if resp.status_code == 200:
            try:
                result_json = resp.json()
            except Exception as e:
                return {"apex": apex, "uuid": uuid, "error": f"json parse error: {e}"}
            try:
                contract, rpc_id = extract_contract(result_json)
            except Exception as e:
                return {"apex": apex, "uuid": uuid, "error": f"extract_contract error: {e}"}
            return {"apex": apex, "uuid": uuid, "contract": contract, "rpc_id": rpc_id}
        if resp.status_code == 429:
            time.sleep(6)
            continue
        if resp.status_code == 404:
            return {"apex": apex, "uuid": uuid, "error": "HTTP 404 (scan expired/removed)"}
        return {"apex": apex, "uuid": uuid, "error": f"HTTP {resp.status_code}"}
    return {"apex": apex, "uuid": uuid, "error": "exhausted retries on 429"}


count_done = 0
count_error = 0
start = time.time()
total = len(remaining)

with open(CHECKPOINT, "a", encoding="utf-8") as ckpt, ThreadPoolExecutor(max_workers=WORKERS) as pool:
    futures = {pool.submit(fetch_one, apex, uuid): apex for apex, uuid in remaining}
    for i, fut in enumerate(as_completed(futures), 1):
        rec = fut.result()
        if "error" in rec:
            count_error += 1
        else:
            count_done += 1
        with write_lock:
            ckpt.write(json.dumps(rec) + "\n")
            ckpt.flush()
        if i % 50 == 0 or i == total:
            elapsed = time.time() - start
            rate = i / elapsed * 60 if elapsed > 0 else 0
            print(f"[{i}/{total}] done={count_done} error={count_error} elapsed={elapsed:.0f}s rate={rate:.1f}/min")

print(f"Finished. done={count_done} error={count_error}")
print(f"Checkpoint file: {CHECKPOINT}")
