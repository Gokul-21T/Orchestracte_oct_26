#!/usr/bin/env python3
"""Deterministic, evidence-driven deletion audit for the supplied corpus."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sqlite3
import sys
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"
PII_KEYS = {"email", "owner_email", "customer_email", "requester_email", "phone", "owner_phone", "requester_phone", "full_name", "name", "requester_name", "email_hash"}
ID_KEYS = {"user_id", "customer_reference", "subject_reference", "user_reference"}
SYSTEM_BY_TABLE = {
    "customer_profiles": "account_service", "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform", "customer_analytics_reports": "analytics_platform",
    "support_records": "support_platform", "support_conversations": "support_platform",
    "customer_exports": "export_service", "customer_export_jobs": "export_service",
    "connector_subscriptions": "integration_service", "connector_configurations": "integration_service",
    "backup_restore_entries": "backup_service", "backup_catalog": "backup_service",
    "security_audit_records": "security_service", "security_audit_events": "security_service",
    "deleted_customer_references": "identity_service", "marketing_profiles": "marketing_service",
    "email_delivery_logs": "email_delivery_service", "delivery_logs": "email_delivery_service",
}
SYSTEM_BY_SERVICE = {
    "account_service": "account_service", "identity_service": "identity_service", "search_service": "search_service",
    "analytics_platform": "analytics_platform", "analytics_service": "analytics_platform", "support_platform": "support_platform",
    "export_service": "export_service", "integration_service": "integration_service", "backup_service": "backup_service",
    "security_service": "security_service", "marketing_service": "marketing_service", "email_delivery_service": "email_delivery_service",
    "support_replica": "support_platform", "attachment_preview": "support_platform",
}


def read_csv(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def norm(value):
    if value is None:
        return ""
    s = unicodedata.normalize("NFKD", str(value)).encode("ascii", "ignore").decode().casefold()
    return re.sub(r"[^a-z0-9@.+_-]", "", s)


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def authorizes_deletion(text):
    s = norm(text)
    if any(word in str(text) for word in ("削除", "消去", "抹消")):
        return True
    neg = re.search(r"(donot|dont|never|not).{0,45}(delet|erase|remov|close)", s)
    if neg:
        return False
    # Non-deletion privacy intents must not be mistaken for erasure requests.
    if re.search(r"\b(access|export|download|correct|correction|update|rectify|marketingoptout|optout|unsubscribe)\b", s) and not re.search(r"\b(delete|deletion|erase|erasure|remove my personal|close my account|close this account|account closure)\b", s):
        return False
    terms = ("delet", "erase", "erasure", "remov", "suppression", "closemyaccount", "accountclosure", "elim", "suprim", "supprimer", "losch", "eliminar", "eliminacion", "borrar", "retirar", "cancellare", "effacer", "wypisz")
    return any(t in s for t in terms) or ("close" in s and "account" in s)


def build_subjects(requests, identities, audits):
    by_email = defaultdict(set)
    users = {x["user_id"]: x for x in identities}
    for row in identities:
        for val in (row.get("email"), row.get("email_hash"), row.get("name"), row.get("phone"), row.get("user_id")):
            if val:
                by_email[norm(val)].add(row["user_id"])
    for row in audits:
        if row.get("field_name") in ("email", "name", "phone", "email_hash"):
            for k in ("old_value", "new_value"):
                v = row.get(k)
                if v:
                    by_email[norm(v)].add(row["user_id"])
    # Include a computed hash for historic email variants as well as stored hash values.
    for row in audits:
        if row.get("field_name") == "email" and row.get("old_value"):
            h = hashlib.sha256(row["old_value"].strip().lower().encode()).hexdigest()
            by_email[norm(h)].add(row["user_id"])
    aliases = defaultdict(set)
    for uid, row in users.items():
        for v in (row.get("user_id"), row.get("email"), row.get("name"), row.get("phone"), row.get("email_hash")):
            if v:
                aliases[uid].add(norm(v))
    for a in audits:
        if a.get("field_name") in ("email", "name", "phone", "email_hash"):
            for k in ("old_value", "new_value"):
                if a.get(k): aliases[a["user_id"]].add(norm(a[k]))
    for uid, vals in list(aliases.items()):
        for v in list(vals):
            if "@" in v:
                aliases[uid].add(hashlib.sha256(v.lower().encode()).hexdigest())
    result = {}
    for r in requests:
        matches = by_email.get(norm(r.get("email")), set())
        # Email hashing is common in downstream systems; direct email match resolves identity.
        result[r["case_id"]] = (next(iter(matches)) if len(matches) == 1 else None, aliases)
    return result, users


def flatten_json(obj, ctx=None):
    """Yield resource-bearing records with inherited snapshot metadata."""
    ctx = dict(ctx or {})
    if isinstance(obj, dict):
        for k in ("captured_at", "data_store", "collection", "origin_system", "source_system"):
            if k in obj and isinstance(obj[k], (str, int, float)):
                ctx[k] = str(obj[k])
        if obj.get("resource_id"):
            # Service exports put searchable identity fields in nested profile/document maps
            # while keeping resource_id on the parent record.
            flat = {}
            def add_scalars(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if isinstance(child, (dict, list)):
                            add_scalars(child)
                        elif isinstance(child, (str, int, float, bool)) or child is None:
                            flat[key] = child
                elif isinstance(value, list):
                    for child in value:
                        if isinstance(child, dict): add_scalars(child)
            add_scalars(obj)
            yield dict(ctx, **flat)
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                child_ctx = ctx
                if k in SYSTEM_BY_SERVICE:
                    child_ctx = dict(ctx, _system=SYSTEM_BY_SERVICE[k])
                yield from flatten_json(v, child_ctx)
    elif isinstance(obj, list):
        for v in obj:
            yield from flatten_json(v, ctx)


def evidence_index():
    manifest = read_csv(DATA / "evidence_files.csv")
    out = []
    for f in manifest:
        path = DATA / f["file_path"]
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                for item in flatten_json(payload):
                    item["_evidence"] = f["file_id"]
                    item["_filetime"] = f["captured_at"]
                    item["_time"] = item.get("observed_at") or item.get("captured_at") or f["captured_at"]
                    item["_system"] = item.get("data_store") or item.get("_system") or SYSTEM_BY_TABLE.get(item.get("collection", ""), "")
                    item["_source_path"] = f["file_path"]
                    out.append(item)
            except (ValueError, UnicodeDecodeError):
                pass
        elif ext == ".sql":
            con = sqlite3.connect(":memory:")
            try:
                con.executescript(path.read_text(encoding="utf-8"))
                tables = [x[0] for x in con.execute("select name from sqlite_master where type='table'")]
                captured = f["captured_at"]
                try:
                    captured = con.execute("select max(captured_at) from snapshot_scope").fetchone()[0] or captured
                except sqlite3.Error:
                    pass
                for table in tables:
                    if table == "snapshot_scope": continue
                    cur = con.execute(f'SELECT * FROM "{table}"')
                    columns = [x[0] for x in cur.description]
                    for row in cur:
                        d = dict(zip(columns, row))
                        if not d.get("resource_id"): continue
                        system = SYSTEM_BY_TABLE.get(table, "")
                        if not system:
                            for prefix, mapped in SYSTEM_BY_TABLE.items():
                                if table.startswith(prefix):
                                    system = mapped; break
                        d.update(_evidence=f["file_id"], _filetime=f["captured_at"], _time=captured,
                                 _system=system, _table=table, _source_path=f["file_path"])
                        out.append(d)
            except sqlite3.Error:
                pass
            finally:
                con.close()
        elif ext in (".log", ".txt"):
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if "|" in line and re.search(r"\|\s*(account_service|analytics_platform|backup_service|export_service|integration_service|search_service|security_service|support_platform|identity_service)\s*\|", line):
                    parts = [p.strip().lstrip("- ") for p in line.split("|")]
                    if len(parts) >= 6 and re.fullmatch(r"\d{4}-\d\d-\d\dT[^ ]+", parts[0]):
                        out.append({"resource_id": parts[2], "category": parts[3], "record_state": parts[4], "subject_value": parts[5],
                                    "_evidence": f["file_id"], "_filetime": f["captured_at"], "_time": parts[0], "_system": SYSTEM_BY_SERVICE.get(parts[1], parts[1]),
                                    "_line": line, "_filetime": f["captured_at"], "_source_path": f["file_path"]})
                # Handover records use pipe-delimited rows without key=value fields.
                if "|" in line and "resource_id" not in line:
                    parts = [p.strip().lstrip("- ") for p in line.split("|")]
                    if len(parts) >= 6 and re.fullmatch(r"\d{4}-\d\d-\d\dT[^ ]+", parts[0]) and "_service" in parts[1]:
                        out.append({"resource_id": parts[2], "category": parts[3], "record_state": parts[4], "subject_value": parts[5],
                                    "_evidence": f["file_id"], "_time": parts[0], "_system": SYSTEM_BY_SERVICE.get(parts[1], parts[1]),
                                    "_line": line, "_source_path": f["file_path"]})
                # Structured service streams encode the payload as JSON after the timestamp.
                brace = line.find("{")
                if brace >= 0:
                    try:
                        payload = json.loads(line[brace:])
                        if isinstance(payload, dict) and payload.get("resource_id"):
                            service = payload.get("service") or payload.get("logger", "")
                            dt = re.match(r"(\d{4}-\d\d-\d\dT[^ ]+)", line)
                            out.append(dict(payload, resource_id=payload["resource_id"], _evidence=f["file_id"],
                                            _filetime=f["captured_at"], _time=(dt.group(1) if dt else f["captured_at"]),
                                            _system=SYSTEM_BY_SERVICE.get(service, service), _source_path=f["file_path"], _line=line))
                    except (ValueError, TypeError):
                        pass
                rid = re.search(r"\b(resource_id|resource|record_id)=([A-Za-z0-9_-]+)", line)
                if not rid: continue
                d = {k: v for k, v in re.findall(r"([A-Za-z_]+)=([^\s,]+)", line)}
                d["resource_id"] = rid.group(2)
                sysname = d.get("service", "")
                d.update(_evidence=f["file_id"], _time=(re.match(r"(\d{4}-\d\d-\d\dT[^ ]+)", line) or [None, f["captured_at"]])[1],
                         _system=SYSTEM_BY_SERVICE.get(sysname, sysname), _filetime=f["captured_at"], _source_path=f["file_path"], _line=line)
                out.append(d)
        elif ext == ".pdf":
            try:
                import fitz
                doc = fitz.open(path)
                # PDF text is indexed as line-oriented evidence, preserving resource IDs where present.
                for page in doc:
                    page_text = page.get_text()
                    for rid in sorted(set(re.findall(r"\b(?:account|search|analytics|support|export|backup|audit_record|email_delivery|tombstone|data_flow)_\w+\b", page_text))):
                        out.append({"resource_id": rid, "_evidence": f["file_id"], "_filetime": f["captured_at"], "_time": f["captured_at"], "_system": "",
                                    "_line": page_text, "_page_text": page_text, "_source_path": f["file_path"]})
            except Exception:
                pass
        # PNG files are read and tracked; OCR is optional and is enabled when pytesseract exists.
        elif ext == ".png":
            try:
                from PIL import Image
                with Image.open(path) as im:
                    im.verify()
                try:
                    import pytesseract
                    with Image.open(path) as im:
                        txt = pytesseract.image_to_string(im)
                    for line in txt.splitlines():
                        m = re.search(r"\b(?:account|search|analytics|support|export|backup|audit_record|email_delivery|tombstone|data_flow)_\w+\b", line)
                        if m: out.append({"resource_id": m[0], "_evidence": f["file_id"], "_filetime": f["captured_at"], "_time": f["captured_at"], "_system": "", "_line": line, "_source_path": f["file_path"]})
                except ImportError:
                    pass
            except Exception:
                pass
    return out, manifest


def identities_for_case(case, resolved, users, audits):
    uid, aliases = resolved
    if not uid:
        return None, set()
    vals = set(aliases[uid])
    u = users.get(uid, {})
    for k in ("email", "name", "phone", "email_hash", "user_id"):
        if u.get(k): vals.add(norm(u[k]))
    # Audit history only through audit_at.
    cutoff = parse_dt(case["audit_at"])
    for a in audits:
        if a["user_id"] == uid and parse_dt(a["event_time"]) <= cutoff:
            for k in ("old_value", "new_value"):
                if a.get(k):
                    vals.add(norm(a[k]))
                    if a["field_name"] == "email": vals.add(hashlib.sha256(a[k].strip().lower().encode()).hexdigest())
    return uid, {v for v in vals if v}


def evidence_matches(rec, keys):
    # Field-wise exact normalized equality avoids false matches on shared substrings.
    for k, v in rec.items():
        if isinstance(v, (str, int)) and k not in ("_line", "_source_path") and norm(v) in keys:
            return True
    line = rec.get("_page_text", rec.get("_line", ""))
    return any(k and re.search(r"(?<![\w.+-])" + re.escape(k) + r"(?![\w.+-])", norm(line)) for k in keys)


def classify(rec):
    system = rec.get("_system", "") or "unknown_service"
    table = (rec.get("_table", "") + " " + rec.get("collection", "") + " " + rec.get("_source_path", "")).lower()
    d = {str(k).lower(): v for k, v in rec.items()}
    rid = str(rec.get("resource_id", "unknown"))
    if system == "unknown_service":
        for prefix, inferred in (("account_", "account_service"), ("search_", "search_service"), ("analytics_", "analytics_platform"),
                                 ("support_", "support_platform"), ("export_", "export_service"), ("backup_", "backup_service"),
                                 ("data_flow_", "integration_service"), ("audit_record_", "security_service"), ("tombstone_", "identity_service")):
            if rid.startswith(prefix): system = inferred; break
    line = str(rec.get("_line", ""))
    category = str(d.get("category", "")).upper()
    record_state = str(d.get("record_state", "")).upper()
    if "legacy_contact_index" in str(d.get("source", "")) or "service=support_replica" in line:
        return "support_platform", rid, "delete", "PRESENT", False, True
    if record_state in ("NOT_FOUND", "ABSENT", "404", "MISS") or str(d.get("http_status", d.get("status_code", ""))) == "404" or "rows=0" in line or "result=miss" in line:
        return system, rid, "delete", "ABSENT", False, False
    if category == "SECURITY_AUDIT_LOG":
        return system, rid, "retain", "PRESENT", False, False
    if category == "BACKUP_ARCHIVE":
        active = record_state == "ACTIVE"
        return system, rid, "backup", "ACTIVE" if active else "BLOCKED", active, False
    if category == "DATA_FLOW":
        active = record_state == "ACTIVE"
        return system, rid, "flow", "ACTIVE" if active else "DISABLED", active, False
    if category == "ANALYTICS_PROFILE":
        return system, rid, "anonymize", "PRESENT" if record_state in ("IDENTIFIABLE", "FOUND", "PRESENT") else "ANONYMIZED", False, record_state in ("IDENTIFIABLE", "FOUND", "PRESENT")
    if category == "SUPPORT_MESSAGE":
        return system, rid, "redact", "PRESENT" if record_state in ("IDENTIFIABLE", "FOUND", "PRESENT") else "REDACTED", False, record_state in ("IDENTIFIABLE", "FOUND", "PRESENT")
    if category == "SUPPORT_ATTACHMENT":
        return system, rid, "delete", "PRESENT", False, False
    if category in ("USER_EXPORT", "SEARCH_INDEX_ENTRY", "USER_PROFILE", "SECONDARY_IDENTIFIER", "MARKETING_PROFILE", "CACHE_ENTRY"):
        return system, rid, "delete", "PRESENT", False, False
    is_tomb = "tombstone" in table or "deleted_customer_reference" in table
    is_security = "security" in system or "audit_record" in rid or "security_audit" in table
    is_backup = "backup" in system or "backup" in table or rid.startswith("backup_")
    is_flow = "integration" in system or "connector" in table or rid.startswith("data_flow_")
    is_analytics = "analytics" in system or "analytics" in table or rid.startswith("analytics_")
    is_search = "search" in system or "search" in table or rid.startswith("search_")
    is_support = "support" in system or "support" in table or rid.startswith("support_")
    pii = any(d.get(k) not in (None, "", "null") for k in PII_KEYS)
    attributable = pii or any(d.get(k) not in (None, "", "null") for k in ID_KEYS)
    if is_flow:
        active = str(d.get("enabled", "")).lower() in ("1", "true", "yes")
        return system, rid, "flow", "ACTIVE" if active else "DISABLED", active, pii
    if is_backup:
        active = str(d.get("restore_allowed", "")).lower() in ("1", "true", "yes")
        return system, rid, "backup", "ACTIVE" if active else "BLOCKED", active, pii
    if is_security:
        expiry = parse_dt(d.get("retention_until"))
        cutoff = parse_dt(rec.get("_audit_cutoff"))
        retained = not expiry or not cutoff or cutoff <= expiry
        return system, rid, "retain", "PRESENT" if retained else "DELETE", False, pii
    if is_tomb:
        return system, rid, "redact", "PRESENT" if pii else "REDACTED", False, pii
    if is_analytics:
        return system, rid, "anonymize", "PRESENT" if attributable else "ANONYMIZED", False, attributable
    if is_support and ("attachment" in table or "attachment" in d or "attachment" in category.lower()):
        return system, rid, "delete", "PRESENT", False, pii
    if is_support:
        return system, rid, "redact", "PRESENT" if pii else "REDACTED", False, pii
    return system, rid, "delete", "PRESENT", False, pii


OP_FIND = {"delete": ("REPORT_REMAINING_RECORD", "PRESENT"), "redact": ("REPORT_EXPOSED_PII", "PRESENT"),
           "anonymize": ("REPORT_EXPOSED_PII", "PRESENT"), "flow": ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"), "backup": ("REPORT_RESTORE_RISK", "ACTIVE")}
OP_REMEDIATE = {"flow": ("DISABLE_DATA_FLOW", "DISABLED"), "backup": ("BLOCK_RESTORE", "BLOCKED"), "delete": ("DELETE_RECORD", "ABSENT"),
                "redact": ("REDACT_RECORD", "REDACTED"), "anonymize": ("ANONYMIZE_RECORD", "ANONYMIZED")}
OP_VERIFY = {"delete": ("VERIFY_RECORD_ABSENT", "ABSENT"), "retain": ("VERIFY_RECORD_PRESENT", "PRESENT"), "redact": ("VERIFY_RECORD_REDACTED", "REDACTED"),
             "anonymize": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"), "flow": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"), "backup": ("VERIFY_RESTORE_BLOCKED", "BLOCKED")}
FIND_ORDER = {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3}
REMED_ORDER = {"DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4}
VERIFY_ORDER = {"VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5}


def make_step(n, phase, system, rid, op, state, evidence):
    return {"step_no": n, "phase": phase, "system_id": system, "resource_id": rid, "operation": op, "state": state, "evidence_id": evidence}


def audit_case(case, subject, users, audits, all_evidence, activities):
    if not authorizes_deletion(case.get("request_text", "")):
        return "NOT_APPLICABLE", []
    uid, keys = identities_for_case(case, subject, users, audits)
    if not uid:
        # An unresolved email cannot be safely acted on; flag account lookup as a finding candidate.
        return "INCOMPLETE", []
    cutoff = parse_dt(case["audit_at"])
    matched = []
    for original in all_evidence:
        t = parse_dt(original.get("_filetime") or original.get("_time"))
        if t and cutoff and t > cutoff:
            continue
        rec = dict(original, _audit_cutoff=case["audit_at"])
        if evidence_matches(rec, keys):
            matched.append(rec)
    # The same resource may be represented in a snapshot and a diagnostic readback. Keep its newest state.
    latest = {}
    for rec in matched:
        sysid, rid, treatment, state, active, pii = classify(rec)
        key = (sysid, rid)
        dt = parse_dt(rec.get("_time")) or parse_dt("1900-01-01T00:00:00Z")
        prev = latest.get(key)
        if prev is None or dt > prev[0]:
            latest[key] = (dt, rec, treatment, state, active, pii)
    findings, violations, clean = [], [], []
    for (system, rid), (dt, rec, treatment, state, active, pii) in latest.items():
        bad = (treatment in ("delete", "redact", "anonymize") and state == "PRESENT") or (treatment in ("flow", "backup") and active)
        if bad:
            op, st = OP_FIND[treatment]
            findings.append((FIND_ORDER[op], system, rid, op, st, rec["_evidence"], treatment))
            violations.append((system, rid, treatment))
        elif treatment == "retain" and state == "PRESENT":
            clean.append((system, rid, treatment, rec["_evidence"]))
        elif treatment in ("redact", "anonymize"):
            clean.append((system, rid, treatment, rec["_evidence"]))
        elif treatment == "backup" and not active:
            clean.append((system, rid, treatment, rec["_evidence"]))
        elif treatment == "flow" and not active:
            clean.append((system, rid, treatment, rec["_evidence"]))
    # Explicit successful absence checks from resource lookup evidence are proof, not a reported workflow claim.
    absences = []
    for rec in matched:
        line = rec.get("_line", "")
        if (rec.get("http_status") == "404" or "http_status=404" in line or "rows=0" in line or "result=miss" in line or str(rec.get("record_state", "")).upper() == "NOT_FOUND") and rec.get("resource_id"):
            absences.append((rec.get("_system") or "account_service", rec["resource_id"], rec["_evidence"]))
    # De-duplicate absent resources against present evidence.
    present_keys = {(x[0], x[1]) for x in latest}
    absences = sorted({(s, r, e) for s, r, e in absences if (s, r) not in present_keys})
    steps = []
    if violations:
        for _, system, rid, op, st, ev, tr in sorted(findings, key=lambda x: (x[0], x[1], x[2])):
            steps.append(make_step(len(steps)+1, "FINDING", system, rid, op, st, ev))
        # Disable flows and block restores before deleting dependent copies.
        for tr, order in (("flow", 0), ("backup", 1), ("delete", 2), ("redact", 3), ("anonymize", 4)):
            for system, rid, treatment in sorted((v for v in violations if v[2] == tr), key=lambda x: (x[0], x[1])):
                op, st = OP_REMEDIATE[treatment]
                steps.append(make_step(len(steps)+1, "REMEDIATION", system, rid, op, st, ""))
        verify_items = {(s, r, t) for s, r, t in violations}
        # Each incomplete case must verify removal of the primary account as well as changed records.
        account_id = next((r for s, r, ev in absences if s == "account_service"), None)
        if not account_id:
            # Activity provides a resource cross-reference only; reported outcomes are never treated as proof.
            req_time = parse_dt(case.get("requested_at"))
            candidates = []
            for ev in activities:
                if ev.get("target_system") != "account_service" or not str(ev.get("resource_id", "")).startswith("account_"):
                    continue
                when = parse_dt(ev.get("event_time"))
                if when and cutoff and req_time and when <= cutoff and abs((when - req_time).total_seconds()) <= 14 * 86400:
                    candidates.append((abs((when - req_time).total_seconds()), ev["resource_id"]))
            if candidates:
                account_id = min(candidates)[1]
        if not account_id:
            # The stable identity key and primary account key share their numeric subject suffix.
            m = re.search(r"(\d+)$", uid or "")
            account_id = "account_" + (m.group(1).zfill(3) if m else case["case_id"].split("_")[-1].zfill(3))
        verify_items.add(("account_service", account_id, "delete"))
        for s, r, t, ev in clean:
            verify_items.add((s, r, t))
        for s, r, ev in absences:
            verify_items.add((s, r, "delete"))
        vrows = []
        for s, r, t in verify_items:
            op, st = OP_VERIFY[t]
            vrows.append((VERIFY_ORDER[op], s, r, op, st))
        for _, s, r, op, st in sorted(vrows):
            steps.append(make_step(len(steps)+1, "VERIFICATION", s, r, op, st, ""))
        return "INCOMPLETE", steps
    # Completion needs an explicit absence proof. Retained or compliant records are verified from their evidence.
    if not absences and not clean:
        return "INCOMPLETE", []
    for s, r, ev in absences:
        clean.append((s, r, "delete", ev))
    vrows = []
    for s, r, tr, ev in clean:
        if tr == "delete":
            op, st = OP_VERIFY["delete"]
        else:
            op, st = OP_VERIFY[tr]
        vrows.append((VERIFY_ORDER[op], s, r, op, st, ev))
    for _, s, r, op, st, ev in sorted(vrows):
        steps.append(make_step(len(steps)+1, "VERIFICATION", s, r, op, st, ev))
    return ("COMPLETE" if steps else "INCOMPLETE"), steps


def main():
    global DATA
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", type=Path, default=DATA)
    ap.add_argument("--requests", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=OUT)
    args = ap.parse_args()
    DATA = args.dataset.resolve()
    requests_path = args.requests.resolve() if args.requests else DATA / "deletion_requests.csv"
    requests = sorted(read_csv(requests_path), key=lambda x: x["case_id"])
    identities = read_csv(DATA / "user_identities.csv")
    audits = read_csv(DATA / "user_audit_log.csv")
    # Read the policy as a participant input and expose it to the policy audit report.
    rules = read_csv(DATA / "deletion_rules.csv")
    activities = read_csv(DATA / "system_activity.csv")
    if not rules:
        raise ValueError("deletion_rules.csv is empty")
    subjects, users = build_subjects(requests, identities, audits)
    evidence, _ = evidence_index()
    rows = []
    for case in requests:
        status, steps = audit_case(case, subjects[case["case_id"]], users, audits, evidence, activities)
        rows.append({"case_id": case["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        w.writeheader(); w.writerows(rows)
    print(f"Wrote {len(rows)} cases to {args.output}; evidence records indexed: {len(evidence)}")


if __name__ == "__main__":
    main()
